import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import shlex


class TestDockerImageImports(unittest.TestCase):
    """Regression test that mimics the Docker COPY layout.

    The test parses the repository's ``Dockerfile`` to discover every ``COPY``
    instruction, reproduces the same file layout in a temporary directory and
    then attempts to import the ``server`` module exactly as the container would
    (``python -B -c 'import server'``).  The original Dockerfile omitted two
    required source files, causing the import to fail; after fixing the Dockerfile
    the import must succeed.
    """

    def setUp(self):
        # Temporary directory that will hold the copied layout
        self.layout_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.layout_dir, ignore_errors=True))

        # Locate repository root (one level above the ``tests`` package)
        self.repo_root = Path(__file__).resolve().parents[1]

        # Parse the Dockerfile for COPY instructions, handling line continuations
        dockerfile_path = self.repo_root / "Dockerfile"
        self.assertTrue(dockerfile_path.is_file(), f"Dockerfile not found at {dockerfile_path}")
        copy_instructions = []
        logical_lines = []
        buffer = ""
        for raw_line in dockerfile_path.read_text().splitlines():
            stripped = raw_line.rstrip()
            # Skip empty lines and comments early
            if not stripped or stripped.lstrip().startswith('#'):
                continue
            if stripped.endswith('\\'):
                # Remove the trailing backslash and keep a space for separation
                buffer += stripped[:-1].rstrip() + ' '
                continue
            else:
                buffer += stripped
                logical_lines.append(buffer.strip())
                buffer = ""
        # In case the file ends with a continuation (unlikely but safe)
        if buffer:
            logical_lines.append(buffer.strip())

        for line in logical_lines:
            if line.upper().startswith('COPY '):
                # Remove the leading "COPY" and split respecting quoted paths
                parts = shlex.split(line[5:])
                # Docker syntax: one or more sources followed by a destination
                self.assertTrue(len(parts) >= 2, f"Malformed COPY instruction: {line}")
                *sources, dest = parts
                copy_instructions.append((sources, dest))

        # Recreate the layout exactly as Docker would
        for sources, dest in copy_instructions:
            # Destination is relative to WORKDIR (/app). Strip any leading './'
            dest_path = self.layout_dir / dest.lstrip("./")
            # Determine if Docker treats the destination as a directory
            is_dir_dest = (len(sources) > 1) or dest.endswith('/') or dest == '.'
            if is_dir_dest:
                dest_path.mkdir(parents=True, exist_ok=True)
            expanded: list[Path] = []
            for src in sources:
                if any(ch in src for ch in "*?["):
                    matches = sorted(self.repo_root.glob(src))
                    self.assertTrue(matches, f"COPY glob matched nothing: {src}")
                    expanded.extend(matches)
                else:
                    expanded.append(self.repo_root / src)
            if len(expanded) > 1:
                is_dir_dest = True
                dest_path.mkdir(parents=True, exist_ok=True)
            for src_path in expanded:
                # Do not silently skip missing sources – they must exist
                self.assertTrue(src_path.exists(), f"COPY source does not exist: {src_path}")
                if src_path.is_dir():
                    if is_dir_dest:
                        # Docker copies *contents* of the source directory into dest_path
                        for item in src_path.iterdir():
                            target = dest_path / item.name
                            if item.is_dir():
                                shutil.copytree(item, target, dirs_exist_ok=True)
                            else:
                                target.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(item, target)
                    else:
                        # Destination is a file path – copy the directory itself
                        target = dest_path / src_path.name
                        shutil.copytree(src_path, target, dirs_exist_ok=True)
                else:
                    # Source is a file
                    target = dest_path / src_path.name if is_dir_dest else dest_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src_path, target)

        # Create a temporary data directory for the SNIPER_DATA_DIR env var
        self.data_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.data_dir, ignore_errors=True))

    def test_import_server_succeeds(self):
        env = os.environ.copy()
        # Docker installs the exact runtime lock before copying sources. Keep
        # the canonical test runner's pinned dependency path while putting the
        # synthetic COPY layout first; replacing PYTHONPATH entirely would
        # incorrectly simulate a dependency-free (pre-runtime-lock) image.
        runtime_path = env.get("PYTHONPATH", "").strip()
        env["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(self.layout_dir), runtime_path) if part
        )
        env["SNIPER_DATA_DIR"] = str(self.data_dir)
        # ``-B`` mirrors the Docker CMD behaviour (no .pyc files)
        result = subprocess.run(
            [sys.executable, "-B", "-c", "import server"],
            cwd=self.layout_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=(
                f"Importing 'server' failed (return code {result.returncode}).\n"
                f"stdout: {result.stdout}\n"
                f"stderr: {result.stderr}"
            ),
        )

if __name__ == "__main__":
    unittest.main()
