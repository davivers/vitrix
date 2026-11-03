"""Replay of an unsaved draft rule against local datasets (Editor)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

DRAFT = """title: Draft
id: 11111111-1111-1111-1111-111111111111
status: test
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|contains: powershell
  condition: sel
level: medium
"""


@pytest.fixture
def client(user_repo):
    return TestClient(create_app(user_repo)), user_repo.parent / "datasets"


def test_lists_datasets_with_event_counts(client):
    c, _ = client
    out = c.get("/api/replay/datasets").json()
    ds = next(d for d in out if d["name"] == "windows_attack_simulation.jsonl")
    assert ds["events"] > 0 and ds["has_expectations"] is True and ds["error"] is None


def test_draft_replay_all_datasets(client):
    c, _ = client
    r = c.post("/api/replay/draft", json={"rule": DRAFT})
    assert r.status_code == 200
    body = r.json()
    d = body["datasets"][0]
    assert d["dataset"] == "windows_attack_simulation.jsonl"
    assert d["matches"] >= 1 and d["events"] >= d["matches"]
    s = d["sample"][0]
    assert s["index"] >= 1 and isinstance(s["event"], dict)
    assert d["duration_ms"] >= 0 and d["error"] is None


def test_expectation_pass_and_fail_by_path(client):
    c, _ = client
    ok = c.post("/api/replay/draft", json={"rule": DRAFT, "path": "windows/powershell_encoded.yml"}).json()
    d = ok["datasets"][0]
    assert d["expectation"] is not None and d["passed"] in (True, False)
    # same draft that matches everything powershell: counts differ from the encoded rule's exact expectation
    wide = c.post("/api/replay/draft", json={"rule": DRAFT.replace("contains: powershell", "contains: ''"),
                                             "path": "windows/powershell_encoded.yml"}).json()
    assert wide["datasets"][0]["passed"] is False and wide["passed"] is False
    assert "expected" in wide["datasets"][0]["message"]


def test_sample_capped(client):
    c, ds = client
    (ds / "big.jsonl").write_text(chr(10).join('{"Image": "C:/x/powershell.exe"}' for _ in range(120)), encoding="utf-8")
    d = c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["big.jsonl"]}).json()["datasets"][0]
    assert d["matches"] == 120 and len(d["sample"]) == 50 and d["truncated"] is True


def test_unsupported_feature_is_an_error_not_a_pass(client):
    c, _ = client
    rule = DRAFT.replace("Image|contains: powershell", "Image|bogusmodifier: x")
    body = c.post("/api/replay/draft", json={"rule": rule}).json()
    d = body["datasets"][0]
    assert d["error"] and d["passed"] is False and body["passed"] is False and body["errors"] == 1


def test_input_guards(client):
    c, ds = client
    (ds.parent / "secret.json").write_text("[]", encoding="utf-8")
    for bad in ["../secret.json", r"..\secret.json", "nope.jsonl", "windows_attack_simulation.expect.yml"]:
        assert c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": [bad]}).status_code == 422
    assert c.post("/api/replay/draft", json={"rule": "a: [", "datasets": None}).status_code == 422
    assert c.post("/api/replay/draft", json={"rule": "title: x"}).status_code == 422
    assert c.post("/api/replay/draft", json={"rule": "x" * 200_001}).status_code == 422
    assert c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["a"] * 51}).status_code == 422


def test_old_replay_payload_still_works(client):
    c, _ = client
    r = c.post("/api/replay", json={"events": '[{"Image": "x/powershell.exe"}]', "rule": DRAFT})
    assert r.status_code == 200 and r.json()["rules"][0]["matches"] == 1


def test_catastrophic_regex_times_out_with_error(client):
    import time

    c, ds = client
    (ds / "evil.jsonl").write_text('{"Image": "' + "a" * 40 + 'b"}', encoding="utf-8")
    rule = DRAFT.replace("Image|contains: powershell", "Image|re: '^(a|aa)+$'")
    t0 = time.perf_counter()
    d = c.post("/api/replay/draft", json={"rule": rule, "datasets": ["evil.jsonl"]}).json()["datasets"][0]
    assert time.perf_counter() - t0 < 5
    assert "timed out" in d["error"] and d["passed"] is False


def test_invalid_regex_and_malformed_detection_are_errors_not_500(client):
    c, _ = client
    r = c.post("/api/replay/draft", json={"rule": DRAFT.replace("Image|contains: powershell", "Image|re: '('")})
    assert r.status_code == 200
    d = r.json()["datasets"][0]
    assert "invalid regex" in d["error"] and d["passed"] is False
    bad = c.post("/api/replay/draft", json={"rule": "title: x\ndetection: 5\n"})
    assert bad.status_code == 200
    assert bad.json()["datasets"][0]["error"] and bad.json()["passed"] is False


def test_no_datasets_is_not_a_pass(client):
    c, ds = client
    for f in ds.iterdir():
        f.unlink()
    body = c.post("/api/replay/draft", json={"rule": DRAFT}).json()
    assert body["datasets"] == [] and body["passed"] is None and body["message"] == "no datasets to replay"


def test_total_regex_budget_across_datasets(client):
    import time

    c, ds = client
    for i in range(8):
        (ds / f"evil{i}.jsonl").write_text('{"Image": "' + "a" * 40 + 'b"}', encoding="utf-8")
    rule = DRAFT.replace("Image|contains: powershell", "Image|re: '^(a|aa)+$'")
    t0 = time.perf_counter()
    r = c.post("/api/replay/draft", json={"rule": rule}).json()
    assert time.perf_counter() - t0 < 6
    assert r["errors"] >= 8 and all(d["passed"] is False for d in r["datasets"] if d["dataset"].startswith("evil"))
