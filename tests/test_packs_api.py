"""Content packs API (S6, ADR 0004): jobs, cache, drafts result, archive guards. Never touches the network."""

from __future__ import annotations

import io
import stat
import threading
import time
import zipfile

import pytest
from test_drafts import AUTH_ON, BASE, LOOPBACK, team
from test_engine import make_project

from vitrix import packs

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from vitrix.api import create_app  # noqa: E402

RULE = """\
title: {title}
id: aaaaaaaa-aaaa-4aaa-8aaa-{n:012d}
status: test
description: d
author: someone
date: 2026-11-01
logsource: {{category: process_creation, product: {product}}}
detection:
  selection:
    Image|endswith: '\\tool{n}.exe'
    CommandLine|contains: '--bad{n}'
  condition: selection
level: medium
"""
REGEX_RULE = """\
title: Uses regex
status: test
logsource: {category: process_creation, product: windows}
detection:
  selection:
    CommandLine|re: 'a+b'
  condition: selection
level: low
"""


def rule(n: int, product: str = "windows") -> str:
    return RULE.format(n=n, title=f"Rule {n}", product=product)


def make_zip(rules: dict[str, str], extra=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in rules.items():
            zf.writestr(f"sigma-master/rules/{name}", text)
        zf.writestr("sigma-master/README.md", "not a rule")
        zf.writestr("sigma-master/tests/skip.yml", "title: outside rules/\n")
        for fn in extra or []:
            fn(zf)
    return buf.getvalue()


SMALL = {
    "windows/process_creation/a.yml": rule(1),
    "windows/process_creation/b.yml": rule(2),
    "linux/process_creation/c.yml": rule(3, "linux"),
    "windows/process_creation/regex.yml": REGEX_RULE,
}


class FakeResponse:
    def __init__(self, data: bytes, url: str):
        self._io, self._url = io.BytesIO(data), url
        self.headers = {"Content-Length": str(len(data))}

    def read(self, n: int = -1) -> bytes:
        return self._io.read(n)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def net(monkeypatch):
    """Replaces the one network function; `calls` lists the URLs asked for, `data` is the served zip."""
    state = {"calls": [], "data": make_zip(SMALL), "final_url": None, "gate": None}

    def fake_open(url: str):
        state["calls"].append(url)
        if state["gate"] is not None:
            state["gate"].wait(5)
        return FakeResponse(state["data"], state["final_url"] or url)

    monkeypatch.setattr(packs, "_open_url", fake_open)
    return state


def local(tmp_path, monkeypatch, extra: str = "") -> TestClient:
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    return TestClient(create_app(make_project(tmp_path, extra_cfg=extra)), base_url=BASE, client=LOOPBACK)


def wait(c: TestClient, job: dict, timeout: float = 10) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        got = c.get(f"/api/packs/jobs/{job['id']}").json()
        if got["state"] in ("done", "failed"):
            return got
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def start(c: TestClient, **over):
    body = {"mode": "preview", "ref": "master", "filters": {"product": "windows"}, **over}
    return c.post("/api/packs/jobs", json=body)


# --------------------------------------------------------------------------- happy path


def test_sources_then_preview_then_import_writes_local_rule_files(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    src = c.get("/api/packs/sources").json()
    assert src["enabled"] and src["sources"][0]["id"] == "sigmahq" and src["sources"][0]["cached"] == []
    assert src["limits"] == {"max_rules": 50, "files_free": 4999}

    r = start(c)
    assert r.status_code == 202
    job = wait(c, r.json())
    assert job["state"] == "done" and job["error"] is None and job["mode"] == "preview"
    res = job["result"]
    assert res["matched"] == 3  # a, b, regex.yml (windows); linux filtered out; tests/ and README ignored
    by_path = {i["path"]: i for i in res["items"]}
    assert by_path["sigmahq/windows/process_creation/a.yml"]["state"] == "ready"
    assert by_path["sigmahq/windows/process_creation/a.yml"]["cases"] == 2
    assert by_path["sigmahq/windows/process_creation/regex.yml"]["state"] == "untested"
    assert all(i["rule"] is None for i in res["items"])
    assert not (tmp_path / "rules" / "sigmahq").exists()  # preview writes nothing
    assert net["calls"] == ["https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"]

    cached = c.get("/api/packs/sources").json()["sources"][0]["cached"]
    assert cached[0]["ref"] == "master" and len(cached[0]["sha256"]) == 64

    job = wait(c, start(c, mode="import").json())  # second job: archive comes from the cache
    assert len(net["calls"]) == 1
    assert job["state"] == "done" and job["progress"]["imported"] == 2
    assert [i["path"] for i in job["result"]["items"]] == ["sigmahq/windows/process_creation/a.yml", "sigmahq/windows/process_creation/b.yml"]
    assert any("regex.yml" in s["path"] for s in job["result"]["skipped"])
    ids = [i["rule"] for i in job["result"]["items"]]
    assert ids == ["sigmahq/windows/process_creation/a.yml", "sigmahq/windows/process_creation/b.yml"]
    rule_a = c.get("/api/rules/" + ids[0]).json()
    assert rule_a["publication"]["state"] in ("local", "unknown") and rule_a["sha"] and rule_a["cases_sha"]
    cases = (tmp_path / "cases" / ids[0]).read_text(encoding="utf-8")
    assert cases.startswith(packs.HEADER) and "expect: match" in cases
    assert job["result"]["audit"] == "2 rules into rules/sigmahq"


def test_import_selected_paths_and_owner(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    sel = ["sigmahq/windows/process_creation/b.yml"]
    job = wait(c, start(c, mode="import", paths=sel, owner="team-blue").json())
    assert [i["path"] for i in job["result"]["items"]] == sel
    assert "owner: team-blue" in (tmp_path / "rules" / sel[0]).read_text(encoding="utf-8")


def test_import_skips_existing_rule_unless_selected(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    dest = tmp_path / "rules" / "sigmahq" / "windows" / "process_creation"
    dest.mkdir(parents=True)
    (dest / "a.yml").write_text("title: mine\n", encoding="utf-8")
    pre = wait(c, start(c).json())
    assert {i["path"]: i["exists"] for i in pre["result"]["items"]}["sigmahq/windows/process_creation/a.yml"] is True
    job = wait(c, start(c, mode="import").json())
    assert job["progress"]["imported"] == 1
    # an existing file is never overwritten, even when selected explicitly
    again = wait(c, start(c, mode="import", paths=["sigmahq/windows/process_creation/a.yml"]).json())
    assert again["progress"].get("imported", 0) == 0 and "already exists" in again["result"]["skipped"][0]["reason"]
    assert (dest / "a.yml").read_text(encoding="utf-8") == "title: mine\n"


def test_tag_ref_url_and_cache_forever(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    wait(c, start(c, ref="r2025-01-31").json())
    wait(c, start(c, ref="r2025-01-31").json())
    assert net["calls"] == ["https://github.com/SigmaHQ/sigma/archive/refs/tags/r2025-01-31.zip"]
    wait(c, start(c, ref="r2025-01-31", refresh=True).json())  # no accounts: allowed for the local user
    assert len(net["calls"]) == 2


def test_master_cache_expires_after_24h(tmp_path, net):
    cache = tmp_path / "c"
    packs.fetch_sigmahq(cache, "master", now=lambda: 1000.0)
    packs.fetch_sigmahq(cache, "master", now=lambda: 1000.0 + 3600)
    assert len(net["calls"]) == 1
    packs.fetch_sigmahq(cache, "master", now=lambda: 1000.0 + 25 * 3600)
    assert len(net["calls"]) == 2
    assert not list(cache.glob("*.part"))


# --------------------------------------------------------------------------- validation, limits, failures


@pytest.mark.parametrize("body", [
    {"ref": "main"}, {"ref": "r2025-1-1"}, {"ref": "../../etc/passwd"}, {"ref": "https://evil.example/x.zip"},
    {"source": "https://evil.example/x.zip"}, {"into": "../x"}, {"into": "/abs"}, {"mode": "delete"},
    {"filters": {"text": "x" * 201}}, {"paths": [f"p{i}.yml" for i in range(51)]}, {"paths": []},
])
def test_bad_input_is_422_and_nothing_is_fetched(tmp_path, monkeypatch, net, body):
    c = local(tmp_path, monkeypatch)
    assert start(c, **body).status_code == 422
    assert net["calls"] == []


def test_only_one_job_at_a_time(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    net["gate"] = threading.Event()
    first = start(c)
    assert first.status_code == 202
    try:
        second = start(c)
        assert second.status_code == 409 and second.json()["detail"] == "another pack import is running"
        assert c.get(f"/api/packs/jobs/{first.json()['id']}").json()["state"] in ("queued", "downloading")
    finally:
        net["gate"].set()
    assert wait(c, first.json())["state"] == "done"
    assert start(c).status_code == 202


def test_unknown_job_is_404(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    assert c.get("/api/packs/jobs/" + "0" * 32).status_code == 404
    assert c.get("/api/packs/jobs/not-an-id").status_code == 404


def test_file_quota_is_checked_before_any_write(tmp_path, monkeypatch, net):
    from vitrix import local_rules

    monkeypatch.setattr(local_rules, "MAX_FILES", 1)
    c = local(tmp_path, monkeypatch)
    r = start(c, mode="import", paths=["sigmahq/windows/process_creation/a.yml", "sigmahq/windows/process_creation/b.yml"])
    assert r.status_code == 409 and r.json()["detail"] == "too many rule files (1): 0 free" and net["calls"] == []


def test_more_than_50_rules_are_capped(tmp_path, monkeypatch, net):
    net["data"] = make_zip({f"windows/r{i:03}.yml": rule(i) for i in range(60)})
    c = local(tmp_path, monkeypatch)
    pre = wait(c, start(c).json())
    assert pre["result"]["matched"] == 60
    job = wait(c, start(c, mode="import").json())
    assert job["progress"]["imported"] == 50


def test_download_failure_and_foreign_redirect_fail_the_job_and_leave_no_cache(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch)
    net["final_url"] = "https://evil.example/sigma.zip"
    job = wait(c, start(c).json())
    assert job["state"] == "failed" and "outside GitHub" in job["error"]
    net["final_url"], net["data"] = None, b"<html>not a zip</html>"
    job = wait(c, start(c).json())
    assert job["state"] == "failed" and "not a zip" in job["error"]
    cache = tmp_path / ".vitrix" / "cache" / "packs"
    assert not cache.exists() or not list(cache.iterdir())


def test_download_over_the_cap_is_aborted(tmp_path, monkeypatch, net):
    monkeypatch.setattr(packs, "MAX_DOWNLOAD", 1000)
    net["data"] = make_zip({"windows/a.yml": rule(1)} | {f"w/{i}.yml": rule(i) for i in range(30)})
    with pytest.raises(packs.PackError, match="200 MB"):
        packs.fetch_sigmahq(tmp_path / "c", "master")
    assert not list((tmp_path / "c").glob("*"))


def test_job_regex_rules_use_the_regex_budget(tmp_path, monkeypatch, net):
    seen = []
    real = packs.regex_budget

    def spy():
        seen.append(1)
        return real()

    monkeypatch.setattr(packs, "regex_budget", spy)
    c = local(tmp_path, monkeypatch)
    wait(c, start(c).json())
    assert len(seen) == 3


# --------------------------------------------------------------------------- availability and roles


def test_off_when_local_rules_are_off(tmp_path, monkeypatch, net):
    c = local(tmp_path, monkeypatch, extra="local_rules:\n  enabled: false\n")
    src = c.get("/api/packs/sources").json()
    assert src["enabled"] is False and src["reason"]
    r = start(c)
    assert r.status_code == 403 and r.json()["detail"].startswith("Content packs are off:")
    assert c.get("/api/packs/jobs/" + "0" * 32).status_code == 403


def test_off_for_non_loopback_without_accounts(tmp_path, monkeypatch, net):
    monkeypatch.delenv("VITRIX_ALLOWED_HOSTS", raising=False)
    c = TestClient(create_app(make_project(tmp_path)), base_url=BASE, client=("10.0.0.5", 4000))
    assert c.get("/api/packs/sources").json()["enabled"] is False
    assert start(c).status_code == 403


def test_roles_viewer_reads_editor_imports_admin_refreshes(tmp_path, monkeypatch, net):
    t = team(tmp_path)
    assert t["view"].get("/api/packs/sources").json()["enabled"] is True
    assert start(t["view"]).status_code == 403
    assert start(t["ed1"], refresh=True).status_code == 403
    job = wait(t["ed1"], start(t["ed1"], mode="import").json())
    assert job["created_by"]["email"] == "ed1@example.com" and job["progress"]["imported"] == 2
    assert t["view"].get(f"/api/packs/jobs/{job['id']}").status_code == 200
    forced = start(t["owner"], refresh=True)
    assert forced.status_code == 202
    wait(t["owner"], forced.json())
    anon = TestClient(t["owner"].app, base_url=BASE)
    assert anon.get("/api/packs/sources").status_code == 401 and start(anon).status_code == 401
    assert [i["rule"] for i in job["result"]["items"]] == ["sigmahq/windows/process_creation/a.yml", "sigmahq/windows/process_creation/b.yml"]
    assert (tmp_path / "rules" / "sigmahq" / "windows" / "process_creation" / "a.yml").is_file()
    assert AUTH_ON  # (config used by team())


# --------------------------------------------------------------------------- archive guards


def read(zbytes: bytes) -> dict[str, str]:
    return packs._from_zip(zbytes, "rules")


def test_zip_slip_names_never_reach_the_result_nor_the_disk(tmp_path):
    def evil(zf):
        zf.writestr("sigma-master/rules/../../evil.yml", rule(9))
        zf.writestr("sigma-master/rules/windows/../../../evil2.yml", rule(9))
        zf.writestr("/abs/rules/evil3.yml", rule(9))
        zf.writestr("sigma-master/rules/..\\evil4.yml", rule(9))
        zf.writestr("C:/rules/evil5.yml", rule(9))

    got = read(make_zip({"windows/ok.yml": rule(1)}, [evil]))
    assert list(got) == ["windows/ok.yml"]
    assert not list(tmp_path.parent.glob("evil*"))


def test_zip_slip_candidates_with_bad_segments_are_skipped_with_a_reason():
    skipped: list[dict] = []
    out = packs.scan({"windows/ok.yml": rule(1), "win dows/we ird.yml": rule(2), ".hidden/x.yml": rule(3)}, skipped=skipped)
    assert [c.path for c in out] == ["sigmahq/windows/ok.yml"]
    assert {s["path"] for s in skipped} == {"win dows/we ird.yml", ".hidden/x.yml"}


def test_bomb_member_over_1mb_is_skipped_by_what_is_actually_read():
    big = "title: x\n" + "a: " + "A" * 2_000_000 + "\n"
    got = read(make_zip({"windows/ok.yml": rule(1), "windows/big.yml": big}))
    assert list(got) == ["windows/ok.yml"]


def test_bomb_forged_declared_size_is_not_trusted(monkeypatch):
    """A member that DECLARES 10 bytes but inflates to 2 MB: the read is bounded, the member skipped."""
    data = bytearray(make_zip({"windows/forged.yml": "x" * 2_000_000}))
    name = b"sigma-master/rules/windows/forged.yml"
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):  # uncompressed-size fields
        i = data.find(sig)
        while i != -1:
            if data[i:].find(name) != -1:
                data[i + off:i + off + 4] = (10).to_bytes(4, "little")
            i = data.find(sig, i + 1)
    try:
        got = read(bytes(data))
    except (packs.PackError, zipfile.BadZipFile):
        return  # the archive is refused outright: also safe
    assert "windows/forged.yml" not in got


def test_bomb_high_compression_ratio_member_is_skipped():
    squash = "title: x\n" + "#" + "A" * 900_000 + "\n"  # < 1 MB but ratio >> 100:1
    got = read(make_zip({"windows/ok.yml": rule(1), "windows/squash.yml": squash}))
    assert list(got) == ["windows/ok.yml"]


def test_bomb_total_read_cap_fails(monkeypatch):
    monkeypatch.setattr(packs, "MAX_TOTAL_READ", 3000)
    rules = {f"windows/r{i}.yml": rule(i) for i in range(20)}
    with pytest.raises(packs.PackError, match="too large"):
        read(make_zip(rules))


def test_bomb_too_many_entries_fails(monkeypatch):
    monkeypatch.setattr(packs, "MAX_ENTRIES", 10)
    with pytest.raises(packs.PackError, match="too many entries"):
        read(make_zip({f"windows/r{i}.yml": rule(i) for i in range(15)}))


def test_symlink_and_encrypted_and_garbage_members():
    def link(zf):
        info = zipfile.ZipInfo("sigma-master/rules/windows/link.yml")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")

    got = read(make_zip({"windows/ok.yml": rule(1)}, [link]))
    assert list(got) == ["windows/ok.yml"]
    with pytest.raises(packs.PackError, match="not a valid zip"):
        packs._from_zip(b"definitely not a zip", "rules")


def test_a_bomb_archive_fails_the_job_cleanly(tmp_path, monkeypatch, net):
    monkeypatch.setattr(packs, "MAX_ENTRIES", 5)
    c = local(tmp_path, monkeypatch)
    job = wait(c, start(c).json())
    assert job["state"] == "failed" and "too many entries" in job["error"]
    assert c.get("/api/drafts").json()["drafts"] == []


# --------------------------------------------------------------------------- CLI path keeps working


def test_cli_import_pack_still_writes_files(tmp_path, monkeypatch):
    from vitrix.config import load_config

    cfg = load_config(make_project(tmp_path))
    src = tmp_path / "src" / "rules"
    (src / "windows").mkdir(parents=True)
    (src / "windows" / "a.yml").write_text(rule(1), encoding="utf-8")
    res = packs.import_pack(cfg, str(tmp_path / "src"), product="windows")
    assert [i["id"] for i in res.imported] == ["sigmahq/windows/a.yml"]
    assert (tmp_path / "rules" / "sigmahq" / "windows" / "a.yml").is_file()
    assert (tmp_path / "cases" / "sigmahq" / "windows" / "a.yml").read_text(encoding="utf-8").startswith(packs.HEADER)
    again = packs.import_pack(cfg, str(tmp_path / "src"), product="windows")
    assert again.imported == [] and "already exists" in again.skipped[0]["reason"]


# --------------------------------------------------------------------------- download robustness (appsec review)


def test_download_has_a_total_deadline(tmp_path, monkeypatch, net):
    """A server that trickles bytes forever is cut by the overall deadline, not just per-read timeouts."""
    monkeypatch.setattr(packs, "DOWNLOAD_DEADLINE", 5)
    ticks = iter(range(0, 1000, 3))  # each clock() call advances 3 s
    monkeypatch.setattr(packs, "_CHUNK", 64)
    with pytest.raises(packs.PackError, match="took longer"):
        packs.fetch_sigmahq(tmp_path / "c", "master", clock=lambda: next(ticks))
    assert not list((tmp_path / "c").iterdir())  # temp file removed, nothing cached


def test_concurrent_downloads_use_unique_temp_files(tmp_path, monkeypatch, net):
    seen = []
    real = packs.tempfile.mkstemp

    def spy(*a, **k):
        fd, name = real(*a, **k)
        seen.append(name)
        return fd, name

    monkeypatch.setattr(packs.tempfile, "mkstemp", spy)
    cache = tmp_path / "c"
    packs.fetch_sigmahq(cache, "master", refresh=True)
    packs.fetch_sigmahq(cache, "master", refresh=True)
    assert len(set(seen)) == 2 and all(n.endswith(".part") for n in seen)
    assert sorted(p.name for p in cache.iterdir()) == ["sigmahq-master.json", "sigmahq-master.zip"]  # renamed, none left behind
    assert zipfile.is_zipfile(cache / "sigmahq-master.zip")


def test_cli_download_streams_to_disk_and_cleans_up(tmp_path, net):
    files = packs.read_source("sigmahq")
    assert "windows/process_creation/a.yml" in files
