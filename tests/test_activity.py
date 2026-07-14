"""The MCP activity log: the API tails this file to show the web UI what the agent is doing."""

import json

import pytest

import lawless_waf.settings as st
from lawless_waf import activity


@pytest.fixture
def activity_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("OFFLINE", "true")
    st._settings = None
    yield tmp_path
    st._settings = None


def test_record_then_read_round_trip(activity_dir):
    activity.record("summary", {"dataset_id": "2026-06-24"}, result={"rules": [1, 2, 3]})

    events = activity.read()
    assert len(events) == 1
    assert events[0]["tool"] == "summary"
    assert events[0]["args"] == {"dataset_id": "2026-06-24"}
    assert events[0]["summary"] == "3 rules"
    assert events[0]["ok"] is True


def test_record_keeps_bulky_and_hostile_args_out_of_the_log(activity_dir):
    """Args are echoed to the UI, so tf_content-sized values get summarized, not stored."""
    activity.record("coverage", {"tf_content": "x" * 5000, "datasets": ["a", "b"], "force": True})

    args = activity.read()[0]["args"]
    assert len(args["tf_content"]) <= 120
    assert args["datasets"] == "[2]"  # lists are summarized by length
    assert args["force"] is True


def test_record_marks_errors(activity_dir):
    activity.record("summary", {"dataset_id": "nope"}, error="dataset not found")

    ev = activity.read()[0]
    assert ev["ok"] is False and ev["summary"] == "dataset not found"


def test_read_filters_by_after(activity_dir):
    activity.record("a")
    activity.record("b")
    first, second = activity.read()

    assert [e["tool"] for e in activity.read(after=first["ts"])] == ["b"]
    assert activity.read(after=second["ts"]) == []


def test_read_limit_returns_the_most_recent(activity_dir):
    for i in range(5):
        activity.record(f"tool{i}")

    assert [e["tool"] for e in activity.read(limit=2)] == ["tool3", "tool4"]


def test_read_skips_corrupt_lines(activity_dir):
    activity.record("summary")
    with (activity_dir / ".activity.jsonl").open("a", encoding="utf-8") as f:
        f.write("not json\n\n")

    assert [e["tool"] for e in activity.read()] == ["summary"]


def test_log_is_trimmed_once_it_outgrows_the_cap(activity_dir):
    """The log lives in the data volume forever, so it must stay bounded."""
    path = activity_dir / ".activity.jsonl"
    path.write_text("".join(json.dumps({"ts": i, "tool": f"old{i}"}) + "\n" for i in range(activity._MAX_LINES)))

    activity.record("newest")  # tips it past _MAX_LINES

    lines = path.read_text().splitlines()
    assert len(lines) == activity._KEEP
    assert json.loads(lines[-1])["tool"] == "newest"  # the trim keeps the most recent events


def test_record_never_raises_when_the_log_is_unwritable(activity_dir, monkeypatch):
    """Logging is best-effort: it must not take an MCP tool call down with it."""
    monkeypatch.setattr(activity, "_path", lambda: activity_dir / "nope" / "x.jsonl")
    monkeypatch.setattr("pathlib.Path.mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("read-only")))

    activity.record("summary")  # must not raise
