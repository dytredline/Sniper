"""18. tur SCA envanteri: gerçek dünya manifest çeşitliliği (npm v1/shrinkwrap, kilitsiz package.json, requirements
içermeleri, pdm/setup/poetry kesin sürümleri, go.mod replace, Maven parent/özellik/yönetilen sürüm, Gradle çok satırlı +
değişken + sürüm kataloğu, alt dizin taraması, hoşgörülü mod)."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import textwrap
import unittest

import dependency_security as ds


def _write(base: Path, rel: str, text: str) -> None:
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")


class InventoryTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "proj"
        self.root.mkdir()

    def inventory(self, **kwargs):
        warnings: list[str] = []
        _root, components, _skipped = ds.discover_inventory(str(self.root), allowed_roots=(self.root.parent,),
                                                            warnings=warnings, **kwargs)
        return {(c["ecosystem"], c["name"], c["version"]): c for c in components}, warnings


class NpmTests(InventoryTestBase):
    def test_lockfile_v1_tree_and_shrinkwrap(self):
        _write(self.root, "package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
            "lodash": {"version": "4.17.4"},
            "JSONStream": {"version": "1.3.2", "dev": True,
                           "dependencies": {"through": {"version": "2.3.8"}}},
            "local": {"version": "file:../local"},
        }}))
        found, _ = self.inventory()
        self.assertIn(("npm", "lodash", "4.17.4"), found)
        self.assertIn(("npm", "through", "2.3.8"), found)
        self.assertEqual(found[("npm", "JSONStream", "1.3.2")].get("scope"), "optional")
        self.assertFalse(any(k[1] == "local" for k in found))

    def test_v2_workspace_entries_and_uppercase_names(self):
        _write(self.root, "npm-shrinkwrap.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "packages/web": {"name": "web", "version": "0.1.0"},
            "node_modules/JSONStream": {"version": "1.3.2"},
        }}))
        found, _ = self.inventory()
        self.assertIn(("npm", "JSONStream", "1.3.2"), found)
        self.assertNotIn(("npm", "web", "0.1.0"), found)

    def test_package_json_without_lock_exact_only(self):
        _write(self.root, "package.json", json.dumps({"dependencies": {"express": "4.16.0", "ms": "=2.0.0",
                                                                        "debug": "^2.6.9"},
                                                       "devDependencies": {"mocha": "5.2.0"}}))
        found, warnings = self.inventory()
        self.assertIn(("npm", "express", "4.16.0"), found)
        self.assertIn(("npm", "ms", "2.0.0"), found)
        self.assertEqual(found[("npm", "mocha", "5.2.0")].get("scope"), "optional")
        self.assertFalse(any(k[1] == "debug" for k in found))
        self.assertTrue(any("1 aralıklı sürüm" in w for w in warnings))

    def test_package_json_ignored_when_lock_exists(self):
        _write(self.root, "package.json", json.dumps({"dependencies": {"express": "4.16.0"}}))
        _write(self.root, "yarn.lock", 'express@^4.0.0:\n  version "4.17.1"\n')
        found, _ = self.inventory()
        self.assertIn(("npm", "express", "4.17.1"), found)
        self.assertNotIn(("npm", "express", "4.16.0"), found)


class PythonTests(InventoryTestBase):
    def test_requirements_includes_continuation_hashes_markers(self):
        _write(self.root, "requirements.txt", """
            -r requirements/base.txt
            Django==2.0.1 \\
                --hash=sha256:abc \\
                --hash=sha256:def
            requests===2.19.0 ; python_version >= "3"
            flask>=1.0
        """)
        _write(self.root, "requirements/base.txt", "PyYAML==5.1  # yorum\n-c ../constraints.txt\n")
        _write(self.root, "constraints.txt", "urllib3==1.24.1\n")
        _write(self.root, "requirements-dev.txt", "pytest==3.0.0\n")
        found, _ = self.inventory()
        for key in (("PyPI", "Django", "2.0.1"), ("PyPI", "requests", "2.19.0"), ("PyPI", "PyYAML", "5.1"),
                    ("PyPI", "urllib3", "1.24.1"), ("PyPI", "pytest", "3.0.0")):
            self.assertIn(key, found)

    def test_include_cannot_escape_project(self):
        outside = self.root.parent / "outside.txt"
        outside.write_text("evil==1.0\n")
        _write(self.root, "requirements.txt", "-r ../outside.txt\nok==1.0\n")
        found, _ = self.inventory()
        self.assertIn(("PyPI", "ok", "1.0"), found)
        self.assertNotIn(("PyPI", "evil", "1.0"), found)

    def test_pdm_setup_and_poetry_exact_pins(self):
        _write(self.root, "pdm.lock", '[[package]]\nname = "jinja2"\nversion = "2.10"\n')
        _write(self.root, "setup.py", "setup(install_requires=['pyjwt==1.5.0', 'six>=1.0'])\n")
        _write(self.root, "setup.cfg", "[options]\ninstall_requires =\n    lxml==4.2.1\n")
        _write(self.root, "pyproject.toml", '[tool.poetry.dependencies]\npython = "^3.8"\npillow = "6.2.0"\n'
                                            'numpy = "^1.16"\n')
        found, _ = self.inventory()
        for key in (("PyPI", "jinja2", "2.10"), ("PyPI", "pyjwt", "1.5.0"), ("PyPI", "lxml", "4.2.1"),
                    ("PyPI", "pillow", "6.2.0")):
            self.assertIn(key, found)
        self.assertFalse(any(k[1] in ("six", "numpy", "python") and k[2] for k in found))


class GoTests(InventoryTestBase):
    def test_replace_directives(self):
        _write(self.root, "go.mod", """
            module example.com/app
            require (
                github.com/gin-gonic/gin v1.6.0
                golang.org/x/net v0.0.1 // indirect
                example.com/local v1.0.0
            )
            replace golang.org/x/net => golang.org/x/net v0.7.0
            replace example.com/local => ./local
        """)
        found, _ = self.inventory()
        self.assertIn(("Golang", "github.com/gin-gonic/gin", "1.6.0"), found)
        self.assertIn(("Golang", "golang.org/x/net", "0.7.0"), found)
        self.assertNotIn(("Golang", "golang.org/x/net", "0.0.1"), found)
        self.assertFalse(any(k[1] == "example.com/local" for k in found))


class MavenTests(InventoryTestBase):
    def test_parent_properties_management_and_modules(self):
        _write(self.root, "pom.xml", """
            <project><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version>
              <properties><jackson.version>${base.version}</jackson.version><base.version>2.9.8</base.version></properties>
              <dependencyManagement><dependencies>
                <dependency><groupId>org.apache.struts</groupId><artifactId>struts2-core</artifactId><version>2.5.10</version></dependency>
              </dependencies></dependencyManagement>
            </project>
        """)
        _write(self.root, "web/pom.xml", """
            <project><parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
              <artifactId>web</artifactId>
              <dependencies>
                <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>${jackson.version}</version></dependency>
                <dependency><groupId>org.apache.struts</groupId><artifactId>struts2-core</artifactId></dependency>
                <dependency><groupId>com.acme</groupId><artifactId>core</artifactId><version>${project.version}</version></dependency>
                <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>[4.0,5.0)</version><scope>test</scope></dependency>
              </dependencies>
            </project>
        """)
        found, _ = self.inventory()
        self.assertIn(("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"), found)
        self.assertIn(("Maven", "org.apache.struts:struts2-core", "2.5.10"), found)
        self.assertIn(("Maven", "com.acme:core", "1.0"), found)
        self.assertEqual(found[("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8")]["manifest"],
                         "web/pom.xml")
        self.assertFalse(any(k[1] == "junit:junit" and k[2] for k in found))

    def test_gradle_multiline_variables_and_catalog(self):
        _write(self.root, "gradle.properties", "springVersion=5.0.0\n")
        _write(self.root, "build.gradle", """
            ext { log4jVersion = '2.14.1' }
            dependencies {
                compile \\
                    'commons-collections:commons-collections:3.2.1',
                    "org.apache.logging.log4j:log4j-core:${log4jVersion}"
                implementation "org.springframework:spring-web:$springVersion"
                implementation group: 'com.google.guava', name: 'guava', version: '20.0'
                implementation 'org.example:dynamic:1.+'
                // implementation 'org.commented:out:1.0'
            }
        """)
        _write(self.root, "gradle/libs.versions.toml", """
            [versions]
            snake = "1.26"
            [libraries]
            snakeyaml = { module = "org.yaml:snakeyaml", version.ref = "snake" }
            okhttp = "com.squareup.okhttp3:okhttp:3.12.0"
        """)
        found, _ = self.inventory()
        for key in (("Maven", "commons-collections:commons-collections", "3.2.1"),
                    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
                    ("Maven", "org.springframework:spring-web", "5.0.0"),
                    ("Maven", "com.google.guava:guava", "20.0"),
                    ("Maven", "org.yaml:snakeyaml", "1.26"),
                    ("Maven", "com.squareup.okhttp3:okhttp", "3.12.0")):
            self.assertIn(key, found)
        self.assertFalse(any(k[1] in ("org.example:dynamic", "org.commented:out") for k in found))


class DiscoveryTests(InventoryTestBase):
    def test_subdirectories_skip_dirs_and_lenient_subdir_errors(self):
        _write(self.root, "services/api/requirements.txt", "django==3.0.0\n")
        _write(self.root, "services/web/package-lock.json", "{bozuk")
        _write(self.root, "node_modules/x/package.json", json.dumps({"dependencies": {"a": "1.0.0"}}))
        _write(self.root, "tests/requirements.txt", "testonly==1.0\n")
        found, warnings = self.inventory()
        self.assertIn(("PyPI", "django", "3.0.0"), found)
        self.assertEqual(found[("PyPI", "django", "3.0.0")]["manifest"], "services/api/requirements.txt")
        self.assertFalse(any(k[1] in ("a", "testonly") for k in found))
        self.assertTrue(any(w.startswith("services/web:") for w in warnings))

    def test_root_error_is_strict_by_default_and_warning_when_lenient(self):
        _write(self.root, "package-lock.json", "{bozuk")
        _write(self.root, "requirements.txt", "flask==0.12\n")
        with self.assertRaises(ds.DependencySecurityError):
            self.inventory()
        found, warnings = self.inventory(lenient=True)
        self.assertIn(("PyPI", "flask", "0.12"), found)
        self.assertTrue(any("package-lock.json" in w for w in warnings))

    def test_symlinked_directory_not_followed(self):
        target = self.root.parent / "elsewhere"
        _write(target, "requirements.txt", "outside==1.0\n")
        (self.root / "link").symlink_to(target, target_is_directory=True)
        found, _ = self.inventory()
        self.assertFalse(any(k[1] == "outside" for k in found))


class OfflineFindingsContractTests(InventoryTestBase):
    def test_offline_findings_uses_lenient_inventory(self):
        _write(self.root, "package-lock.json", "{bozuk")
        _write(self.root, "requirements.txt", "flask==0.12\n")
        from unittest import mock
        import osv_offline

        doc = {"document": {"results": [{"packages": [{"package": {"ecosystem": "PyPI", "name": "flask",
                                                                    "version": "0.12"},
                                                        "vulnerabilities": [{"id": "PYSEC-1", "aliases": ["CVE-1"]}]}]}]},
               "coverage": [], "skipped": {}, "warnings": [], "oldest_db_retrieved_utc": ""}
        with mock.patch.object(osv_offline, "match_components", return_value=doc) as matcher:
            rows = ds.offline_vulnerability_findings(str(self.root), allowed_roots=(self.root.parent,))
        names = {(c["name"], c["version"]) for c in matcher.call_args[0][0]}
        self.assertIn(("flask", "0.12"), names)
        self.assertEqual(rows, [{"ecosystem": "PyPI", "name": "flask", "version": "0.12", "ids": ["CVE-1", "PYSEC-1"]}])


if __name__ == "__main__":
    unittest.main()
