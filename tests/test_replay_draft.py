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
    assert ds["events"] > 0 and ds["has_expectations"] is False and ds["error"] is None


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
    c, ds = client
    (ds / "windows_attack_simulation.expect.yml").write_text("expect:\n  windows/powershell_encoded.yml: 2\n", encoding="utf-8")
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
    assert d["error"]["code"] == "regex-timeout" and "timed out" in d["error_text"] and d["error"]["hint"] and d["passed"] is False


def test_invalid_regex_and_malformed_detection_are_errors_not_500(client):
    c, _ = client
    r = c.post("/api/replay/draft", json={"rule": DRAFT.replace("Image|contains: powershell", "Image|re: '('")})
    assert r.status_code == 200
    d = r.json()["datasets"][0]
    assert d["error"]["code"] == "invalid-regex" and "invalid regex" in d["error_text"] and d["passed"] is False
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


# ---- structured errors, cases in the same call, compare with the saved version --------------


def test_structured_errors_and_422_detail(client):
    c, ds = client
    r = c.post("/api/replay/draft", json={"rule": "title: x"})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "invalid-rule" and r.json()["detail"]["hint"]
    assert c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["nope.jsonl"]}).json()["detail"]["code"] == "bad-dataset"
    (ds / "broken.json").write_text("[1, 2]", encoding="utf-8")
    d = c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["broken.json"]}).json()["datasets"][0]
    assert d["error"]["code"] == "bad-dataset" and d["error"]["dataset"] == "broken.json" and d["error"]["hint"] and d["error_text"]
    cidr = DRAFT.replace("Image|contains: powershell", "Image|cidr: 10.0.0.0/8")
    d = c.post("/api/replay/draft", json={"rule": cidr, "datasets": ["windows_attack_simulation.jsonl"]}).json()["datasets"][0]
    assert d["error"]["code"] == "unsupported" and "cidr" in d["error"]["message"] and d["error"]["hint"]


CASES = r"""cases:
  - name: ps fires
    expect: match
    event: {Image: 'C:\Windows\System32\powershell.exe'}
  - name: cmd quiet
    expect: no_match
    event: {Image: 'C:\Windows\System32\cmd.exe'}
  - name: wrong expectation
    expect: match
    event: {Image: 'C:\Windows\System32\calc.exe'}
"""


def test_cases_in_the_same_call_with_selection_detail(client):
    c, _ = client
    body = c.post("/api/replay/draft", json={"rule": DRAFT, "cases": CASES}).json()
    cs = {x["name"]: x for x in body["cases"]}
    assert cs["ps fires"]["passed"] is True and cs["ps fires"]["matched"] is True and cs["ps fires"]["expected"] == "match"
    assert cs["cmd quiet"]["passed"] is True and cs["cmd quiet"]["kind"] == "negative"
    bad = cs["wrong expectation"]
    assert bad["passed"] is False and bad["matched"] is False and bad["hint"]
    sel = bad["selections"][0]
    assert sel["name"] == "sel" and sel["matched"] is False
    f = sel["fields"][0]
    assert f["field"] == "Image|contains" and f["expected"] == "powershell" and f["actual"].endswith("calc.exe") and f["matched"] is False
    assert body["cases_passed"] is False


def test_compare_with_saved_version(client):
    c, ds = client
    lines = ['{"Image": "a/powershell.exe"}', '{"Image": "a/cmd.exe"}', '{"Image": "a/pwsh.exe"}']
    (ds / "tiny.jsonl").write_text("\n".join(lines), encoding="utf-8")
    rules = c.get("/api/rules").json()
    rid = (rules[0].get("id") or rules[0].get("path") or rules[0].get("rel")) if isinstance(rules, list) else None
    assert rid, rules
    base = c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["tiny.jsonl"], "compare": True}).json()
    b0 = base["datasets"][0]
    assert base["saved"] is False and b0["before"] is None and b0["matches"] == 1 and [x["index"] for x in b0["added"]] == [1], base
    out = c.post("/api/replay/draft", json={"rule": DRAFT, "datasets": ["tiny.jsonl"], "compare": True, "path": rid}).json()
    d = out["datasets"][0]
    assert out["saved"] is True and isinstance(d["before"], int)
    assert d["added_total"] == len(d["added"]) and all("event" in x and "index" in x for x in d["added"] + d["removed"])
    assert not {x["index"] for x in d["added"]} & {x["index"] for x in d["removed"]}


def test_regex_timeout_in_a_case_is_regex_timeout_not_unsupported(client):
    c, _ = client
    rule = DRAFT.replace("Image|contains: powershell", "Image|re: '^(a|aa)+$'")
    cases = "cases:\n  - name: evil\n    expect: no_match\n    event: {Image: '" + "a" * 60 + "b'}\n"
    case = c.post("/api/replay/draft", json={"rule": rule, "cases": cases, "datasets": []}).json()["cases"][0]
    assert case["error"]["code"] == "regex-timeout" and "Regex Workbench" in case["error"]["hint"]
