"""The seeded sample: what an offline visitor sees before they ever touch Azure."""

import json

from lawless_waf.sample import DEFAULT_DATE, FP_IP, records, write_sample


def _times(path):
    return [json.loads(line)["time"] for line in path.read_text().splitlines()]


def test_records_are_stamped_with_the_day_they_are_written_to(tmp_path):
    """A dataset id of 2026-06-25 whose records all say 2026-01-01 makes the timeline lie."""
    p = write_sample(tmp_path / "2026-06-25" / "merged.json")
    assert all(t.startswith("2026-06-25T") for t in _times(p))


def test_hour_datasets_take_the_date_from_the_day_directory(tmp_path):
    p = write_sample(tmp_path / "2026-06-25" / "h10" / "merged.json")
    assert all(t.startswith("2026-06-25T") for t in _times(p))


def test_path_without_a_date_falls_back_to_the_default(tmp_path):
    p = write_sample(tmp_path / "merged.json")
    assert all(t.startswith(f"{DEFAULT_DATE}T") for t in _times(p))


def test_activity_is_spread_across_the_day(tmp_path):
    """A single timestamp renders the Overview chart as one full-width bar (00:00 → 00:00)."""
    hours = {r["time"][11:13] for r in records()}
    assert len(hours) >= 4


def test_resolved_day_drops_only_the_false_positive_traffic(tmp_path):
    """`--resolved` is the same day after its exclusion shipped, so a diff of the two days shows
    the cookie false positive resolved while the scanner keeps firing the same rule."""
    def cookie_hits(recs):
        return sum(
            1
            for r in recs
            for m in r["properties"]["details"]["matches"]
            if m["matchVariableName"] == "CookieValue:sessionId"
        )

    assert cookie_hits(records()) > 0
    after = records(false_positives=False)
    assert cookie_hits(after) == 0
    assert not any(r["properties"]["clientIP"] == FP_IP for r in after if r["properties"]["action"] == "Block")
    assert any(r["properties"]["action"] == "Block" for r in after)  # the scanner still blocks
