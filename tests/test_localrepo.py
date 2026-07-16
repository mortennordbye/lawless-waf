"""Reading a waf-exclusions.tf from a local file / git ref, with the path confined to the root."""

import subprocess

import pytest

from lawless_waf import localrepo
from lawless_waf.localrepo import ExclusionsSource, LocalExclusionsError
from lawless_waf.settings import Settings

TF = 'exclusion { match_variable = "RequestCookieNames" operator = "Equals" selector = "sessionId" }\n'


def _settings(root, data_dir) -> Settings:
    return Settings(exclusions_root=str(root), data_dir=data_dir)


def test_read_working_tree_file(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "waf-exclusions.tf").write_text(TF)
    s = _settings(root, tmp_path / "data")

    out = localrepo.read_exclusions(s, "waf-exclusions.tf")
    assert out["content"] == TF
    assert out["from_git"] is False and out["resolved_commit"] is None


def test_path_traversal_outside_root_is_rejected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("nope")
    s = _settings(root, tmp_path / "data")

    with pytest.raises(LocalExclusionsError, match="outside the allowed"):
        localrepo.read_exclusions(s, "../secret.txt")


def test_missing_file_is_a_clear_error(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    s = _settings(root, tmp_path / "data")
    with pytest.raises(LocalExclusionsError, match="not found"):
        localrepo.read_exclusions(s, "waf-exclusions.tf")


def test_feature_disabled_when_root_unset(tmp_path):
    s = Settings(exclusions_root="", data_dir=tmp_path / "data")
    with pytest.raises(LocalExclusionsError, match="not configured"):
        localrepo.read_exclusions(s, "waf-exclusions.tf")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "safe.directory=*", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_read_at_git_ref_reads_committed_version_not_working_tree(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    f = root / "waf-exclusions.tf"
    f.write_text(TF)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "committed exclusions")
    # Change the working tree AFTER committing: reading at the branch must return the committed one.
    f.write_text(TF + '# uncommitted line\n')
    s = _settings(root, tmp_path / "data")

    # Determine the default branch name (portable across git versions).
    branch = subprocess.run(
        ["git", "-c", "safe.directory=*", "rev-parse", "--abbrev-ref", "HEAD"],
        cwd=root, capture_output=True, text=True,
    ).stdout.strip()

    out = localrepo.read_exclusions(s, "waf-exclusions.tf", ref=branch)
    assert out["content"] == TF  # committed version, without the uncommitted line
    assert out["from_git"] is True and out["resolved_commit"]

    # The working tree read sees the uncommitted change.
    wt = localrepo.read_exclusions(s, "waf-exclusions.tf")
    assert "# uncommitted line" in wt["content"]


def test_unknown_ref_is_a_clear_error(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "waf-exclusions.tf").write_text(TF)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "x")
    s = _settings(root, tmp_path / "data")
    with pytest.raises(LocalExclusionsError, match="unknown git ref"):
        localrepo.read_exclusions(s, "waf-exclusions.tf", ref="nonexistent-branch")


def test_ref_on_non_git_dir_is_a_clear_error(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "waf-exclusions.tf").write_text(TF)
    s = _settings(root, tmp_path / "data")
    with pytest.raises(LocalExclusionsError, match="not inside a git repository"):
        localrepo.read_exclusions(s, "waf-exclusions.tf", ref="main")


def test_source_persistence_round_trips(tmp_path):
    s = _settings(tmp_path / "repo", tmp_path / "data")
    (tmp_path / "repo").mkdir()
    src = ExclusionsSource(path="waf/exclusions.tf", ref="main")
    localrepo.save_source(s, src)
    assert localrepo.load_source(s) == src


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """A TestClient whose app has EXCLUSIONS_ROOT pointing at a repo dir with a committed file."""
    from fastapi.testclient import TestClient

    import lawless_waf.settings as st
    from lawless_waf.ratelimit import limiter

    root = tmp_path / "repo"
    root.mkdir()
    (root / "waf-exclusions.tf").write_text(TF)

    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OFFLINE", "true")
    monkeypatch.setenv("EXCLUSIONS_ROOT", str(root))
    st._settings = None
    limiter.enabled = False

    from lawless_waf.main import create_app

    yield TestClient(create_app(), base_url="http://localhost")
    st._settings = None
    limiter.enabled = True


def test_source_config_and_local_read_endpoints(api_client):
    avail = api_client.get("/api/exclusions/source").json()
    assert avail["available"] is True

    saved = api_client.put("/api/exclusions/source", json={"path": "waf-exclusions.tf", "ref": ""})
    assert saved.status_code == 200 and saved.json()["source"]["path"] == "waf-exclusions.tf"

    # GET /local with no params uses the saved source.
    read = api_client.get("/api/exclusions/local")
    assert read.status_code == 200
    assert read.json()["content"] == TF and read.json()["from_git"] is False


def test_local_read_traversal_rejected_at_endpoint(api_client):
    r = api_client.get("/api/exclusions/local", params={"path": "../../etc/passwd"})
    assert r.status_code == 400 and "outside the allowed" in r.json()["detail"]
