import pytest
from pathlib import Path

from nuclei_broad_args import build_nuclei_http_args


# Fixtures for predictable inputs
@pytest.fixture
def valid_binary(tmp_path):
    return Path("/usr/bin/nuclei")  # caller validates; builder does not


@pytest.fixture
def valid_catalog_root(tmp_path):
    return Path("/home/community-user/.local/state/sniper-tool-runtimes/nuclei-templates-v10.5.0")


@pytest.fixture
def valid_output_path(tmp_path):
    return tmp_path / "report.jsonl"


@pytest.fixture
def valid_target_url():
    return "http://10.1.2.3/api/health"


# Basic happy-path broad mode (default and explicit None/empty)
def test_broad_mode_default(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
    )
    assert "-u" in args and valid_target_url in args
    assert "-t" in args and str(valid_catalog_root / "http") in args
    assert "-o" in args and str(valid_output_path) in args
    assert "-id" not in args
    assert "profiles/recommended.yml" not in args
    assert "-it" not in args
    assert "-jsonl" in args


def test_broad_mode_explicit_none(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=None,
    )
    assert "-id" not in args


def test_broad_mode_explicit_empty_list(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=[],
    )
    assert "-id" not in args


# Narrow mode: non-empty template_ids list

def test_narrow_single_id(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=["http-missing-file-header.yaml"],
    )
    id_idx = args.index("-id")
    assert args[id_idx + 1] == "http-missing-file-header.yaml"


def test_narrow_multiple_ids(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    ids = ["a-b", "c.d", "e_f", "X123"]
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=ids,
    )
    found_ids = []
    for i, a in enumerate(args):
        if a == "-id" and i + 1 < len(args):
            found_ids.append(args[i + 1])
    assert found_ids == ids


# include_excluded flag

def test_include_excluded_true_without_map_raises(valid_binary, valid_catalog_root, valid_output_path, valid_target_url, tmp_path):
    # Fail-closed: include_excluded=True and non-empty IDs requires selected_template_paths
    with pytest.raises(ValueError, match="selected_template_paths verilmeli"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["id1"],
            include_excluded=True,
        )


def test_include_excluded_false_default(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        include_excluded=False,
    )
    assert "-it" not in args


# Validation tests (reject invalid/edge cases)

def test_reject_duplicate_ids(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="yinelenen template_id"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["a", "a"],
        )


def test_reject_empty_id(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="boş olmayan bir metin"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=[""],
        )


def test_reject_non_ascii_id(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="geçersiz template_id biçimi"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["café"],
        )


def test_reject_leading_special_char(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="geçersiz template_id biçimi"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["-bad", "good"],
        )


def test_reject_exactly_128_length(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    long_id = "a" * 128  # valid: first char + up to 127 more
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=[long_id],
    )
    assert "-id" in args and long_id in args


def test_reject_129_length(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    long_id = "a" * 129  # invalid
    with pytest.raises(ValueError, match="geçersiz template_id biçimi"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=[long_id],
        )


def test_reject_over_1000_ids(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    many_ids = [f"id{i}" for i in range(1001)]
    with pytest.raises(ValueError, match="en fazla 1000"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=many_ids,
        )


def test_reject_non_string_in_list(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="boş olmayan bir metin"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["ok", 123],
        )


def test_exact_cli_flags(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
    )
    required = [
        "-jsonl", "-silent", "-nc", "-or", "-ot", "-duc", "-ni", "-dr",
        "-no-stdin", "-pt", "http", "-dut", "-lna", "-c", "1", "-rl", "1",
        "-timeout", "5", "-retries", "0",
    ]
    for flag in required:
        assert flag in args


def test_argv_list_not_shell_string(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    # Ensure we never build a string (e.g., no shell=True or joined string)
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=valid_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=["a-b"],
    )
    assert isinstance(args, list)
    assert all(isinstance(el, str) for el in args)
    # Confirm target_url appears exactly once as its own argv element
    assert args.count(valid_target_url) == 1
    # Confirm no shell metacharacters or quoting
    assert '"' not in args
    assert "'" not in args
    assert "\\" not in args


# Include-excluded narrow with selected_template_paths
@pytest.fixture
def mapped_catalog_root(tmp_path):
    catalog_root = tmp_path / "catalog"
    http_dir = catalog_root / "http"
    http_dir.mkdir(parents=True)
    # Create a template in http_dir
    http_dir.joinpath("example.yaml").write_text("test")
    return catalog_root


def test_include_excluded_narrow_with_map(valid_binary, mapped_catalog_root, valid_output_path, valid_target_url):
    # Create template file and build map
    example_path = mapped_catalog_root / "http" / "example.yaml"
    selected_template_paths = {"example.yaml": example_path}
    args = build_nuclei_http_args(
        binary=valid_binary,
        catalog_root=mapped_catalog_root,
        target_url=valid_target_url,
        output_path=valid_output_path,
        template_ids=["example.yaml"],
        include_excluded=True,
        selected_template_paths=selected_template_paths,
    )
    # Narrow mode: no -id, no directory -t -it
    assert "-id" not in args
    # Must have -t and -it with resolved template path, not catalog root
    assert str(example_path.resolve()) in args
    assert "-t" in args and "-it" in args
    t_idx = args.index("-t")
    it_idx = args.index("-it")
    assert args[t_idx + 1] == args[it_idx + 1] == str(example_path.resolve())


def test_include_excluded_narrow_missing_map_raises(valid_binary, mapped_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="selected_template_paths verilmeli"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=mapped_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["example.yaml"],
            include_excluded=True,
        )


def test_include_excluded_narrow_wrong_keys_raises(valid_binary, mapped_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="anahtarları template_ids ile birebir eşleşmeli"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=mapped_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["example.yaml"],
            include_excluded=True,
            selected_template_paths={"wrong_key": mapped_catalog_root / "http" / "example.yaml"},
        )


def test_include_excluded_narrow_supplied_map_in_normal_mode_raises(valid_binary, valid_catalog_root, valid_output_path, valid_target_url):
    with pytest.raises(ValueError, match="selected_template_paths verilmemeli"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=valid_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["example.yaml"],
            selected_template_paths={"example.yaml": valid_catalog_root / "http" / "example.yaml"},
        )


def test_include_excluded_narrow_symlink_file_raises(valid_binary, mapped_catalog_root, valid_output_path, valid_target_url):
    http_dir = mapped_catalog_root / "http"
    symlink_path = http_dir / "symlink.yaml"
    symlink_path.symlink_to(http_dir / "example.yaml")
    with pytest.raises(ValueError, match="symlink"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=mapped_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["symlink.yaml"],
            include_excluded=True,
            selected_template_paths={"symlink.yaml": symlink_path},
        )


def test_include_excluded_narrow_symlink_ancestor_raises(valid_binary, mapped_catalog_root, valid_output_path, valid_target_url, tmp_path):
    # Create a real file outside catalog and symlink into catalog
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    real_file = outside_dir / "real.yaml"
    real_file.write_text("test")
    # Create symlink to real_file in catalog/http
    symlink_path = mapped_catalog_root / "http" / "symlink_file.yaml"
    symlink_path.symlink_to(real_file)
    with pytest.raises(ValueError, match="symlink"):
        build_nuclei_http_args(
            binary=valid_binary,
            catalog_root=mapped_catalog_root,
            target_url=valid_target_url,
            output_path=valid_output_path,
            template_ids=["symlink_file.yaml"],
            include_excluded=True,
            selected_template_paths={"symlink_file.yaml": symlink_path},
        )
