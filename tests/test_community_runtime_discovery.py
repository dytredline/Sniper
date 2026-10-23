from pathlib import Path

import tool_runtime_autodiscover as discovery


def test_public_runtime_discovery_never_probes_private_migration_workspaces(monkeypatch, tmp_path: Path) -> None:
    """Community discovery may use portable/configured roots, never a developer migration tree."""
    observed: list[Path] = []

    def first_file(candidates, *, executable=False):
        observed.extend(Path(item) for item in candidates)
        return None

    def first_exec(candidates, revoked_digests):
        observed.extend(Path(item) for item in candidates)
        return None, None

    def first_dir(candidates):
        observed.extend(Path(item) for item in candidates)
        return None

    monkeypatch.setattr(discovery.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(discovery, "_first_valid_file", first_file)
    monkeypatch.setattr(discovery, "_first_valid_unrevoked_executable", first_exec)
    monkeypatch.setattr(discovery, "_first_valid_dir", first_dir)
    monkeypatch.setattr(discovery, "_read_systemd_dropin_defaults", lambda _path: {})
    monkeypatch.setattr(discovery, "_is_regular_file", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(discovery, "_sha256_file", lambda _path: None)

    bindings, tools = discovery._discover_bindings()

    assert set(bindings) == {
        "SNIPER_SCHEMATHESIS_ALLOWED_PORTS",
        "SNIPER_SCHEMATHESIS_EPHEMERAL_FIXTURE",
        "SNIPER_SCHEMATHESIS_LOCAL_ORIGIN",
    }
    assert tools
    rendered = "\n".join(str(path) for path in observed)
    assert "/runtime-prereqs/" not in rendered
    assert "osv-local-active-analysis-" not in rendered
