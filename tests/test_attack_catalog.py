"""Local ATT&CK catalogue: loader, coverage `catalog`, unknown-technique lint warning."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from vitrix import attack, flow
from vitrix.api import create_app
from vitrix.config import load_config
from vitrix.lint import lint_files
from vitrix.loader import RuleFile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import update_attack_catalog as upd  # noqa: E402


def test_catalog_shape():
    c = attack.catalog()
    assert c["version"] != "unknown" and c["source"].startswith("https://")
    tactic_ids = {t["id"] for t in c["tactics"]}
    assert [t["order"] for t in c["tactics"]] == list(range(len(c["tactics"])))
    assert {"TA0002", "TA0043"} <= tactic_ids
    by_id = {t["id"]: t for t in c["techniques"]}
    assert by_id["T1059.001"]["parent"] == "T1059" and by_id["T1059.001"]["tactics"] == ["TA0002"]
    assert "parent" not in by_id["T1059"]
    assert all(set(t["tactics"]) <= tactic_ids for t in c["techniques"])
    assert [t["id"] for t in c["techniques"]] == sorted(by_id)  # deterministic
    assert attack.is_known_technique("t1059.001") and not attack.is_known_technique("T9999")


def test_update_script_filters_revoked_and_deprecated():
    def tech(i, sid, **kw):
        return {"type": "attack-pattern", "id": sid, "name": i, "external_references": [{"source_name": "mitre-attack", "external_id": i}],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}], **kw}
    bundle = {"objects": [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution", "x_mitre_shortname": "execution",
         "external_references": [{"source_name": "mitre-attack", "external_id": "TA0002"}]},
        {"type": "x-mitre-matrix", "id": "m", "tactic_refs": ["x-mitre-tactic--1"]},
        tech("T1", "attack-pattern--a"), tech("T2", "attack-pattern--b", revoked=True),
        tech("T3", "attack-pattern--c", x_mitre_deprecated=True), tech("T1.001", "attack-pattern--d"),
        {"type": "relationship", "relationship_type": "subtechnique-of", "source_ref": "attack-pattern--d", "target_ref": "attack-pattern--a"},
    ]}
    out = upd.build(bundle)
    assert [t["id"] for t in out["techniques"]] == ["T1", "T1.001"]
    assert out["techniques"][1]["parent"] == "T1" and out["tactics"] == [{"id": "TA0002", "name": "Execution", "order": 0}]


def test_coverage_has_catalog(user_repo):
    cfg = load_config(str(user_repo))
    cov = flow.coverage(cfg)
    assert cov["catalog"]["techniques"] and cov["catalog"]["tactics"]
    client = TestClient(create_app(str(user_repo)), base_url="http://127.0.0.1:8000")
    body = client.get("/api/coverage").json()
    assert body["catalog"]["version"] == attack.catalog()["version"]
    json.dumps(body)


def _rule(tags):
    text = ("title: T\nid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\nstatus: test\nlevel: low\ndescription: d\nfalsepositives: [none]\n"
            f"tags: {tags}\nlogsource: {{product: windows, category: process_creation}}\n"
            "detection:\n  s:\n    Image|endswith: x.exe\n  condition: s\n")
    import yaml
    return RuleFile(Path("r.yml"), "r.yml", text, [yaml.safe_load(text)])


def test_unknown_technique_is_a_warning_not_an_error():
    issues = lint_files([_rule("[attack.execution, attack.t9999]")], {"splunk"})
    msgs = [(i.severity, i.message) for i in issues if "technique" in i.message and "unknown" in i.message]
    assert msgs and msgs[0][0] == "warning" and "t9999" in msgs[0][1]
    ok = lint_files([_rule("[attack.execution, attack.t1059.001]")], {"splunk"})
    assert not [i for i in ok if "unknown ATT&CK technique" in i.message]
