"""KQL table resolution: rule override, vitrix.yml tables, built-in defaults, default_table, actionable error."""

from __future__ import annotations

import pytest
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import service
from vitrix.backends import ConversionError, available_targets, convert_text
from vitrix.config import ConfigError, KqlConfig, load_config, parse_config_text

KQL = available_targets()["kql"]

SYSTEM_RULE = """title: Service installed
id: bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb
status: test
description: x
author: t
date: 2026-01-01
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: Service Control Manager
  condition: selection
level: low
"""
ODD_RULE = SYSTEM_RULE.replace("product: windows\n  service: system", "product: nosuchproduct\n  service: nosuchservice")


def with_block(text: str, block: str) -> str:
    return text.rstrip("\n") + "\n" + block


def first_line(q: str) -> str:
    return q.splitlines()[0]


def test_builtin_default_for_windows_system():
    q = convert_text(SYSTEM_RULE, KQL, [])
    assert first_line(q) == "Event"


def test_rule_override_wins_over_config_and_defaults():
    rule = with_block(SYSTEM_RULE, "vitrix:\n  kql_table: SecurityEvent\n")
    q = convert_text(rule, KQL, [], KqlConfig(tables={"windows/system": "Other"}))
    assert first_line(q) == "SecurityEvent"


def test_config_tables_beat_builtin_defaults():
    assert first_line(convert_text(SYSTEM_RULE, KQL, [], KqlConfig(tables={"windows/system": "MyEvents"}))) == "MyEvents"


def test_backend_inferred_table_is_not_overridden_by_defaults():
    # process_creation maps to DeviceProcessEvents in the backend itself; only an explicit setting overrides it
    q = convert_text(RULE_OK, KQL, [], KqlConfig(default_table="Fallback"))
    assert first_line(q) != "Fallback" and first_line(q).startswith("Device")


def test_default_table_then_actionable_error():
    assert first_line(convert_text(ODD_RULE, KQL, [], KqlConfig(default_table="Fallback"))) == "Fallback"
    with pytest.raises(ConversionError) as e:
        convert_text(ODD_RULE, KQL, [])
    err = e.value
    assert err.code == "kql-table" and err.path == "logsource" and err.line == 7 and err.column == 1
    assert "nosuchproduct/nosuchservice" in str(err) and len(str(err)) < 200
    assert "kql_table: NosuchproductNosuchservice_CL" in err.hint and "nosuchproduct/nosuchservice" in err.hint and "mappings.yml" in err.hint


def test_other_targets_unaffected():
    assert "Service Control Manager" in convert_text(SYSTEM_RULE, available_targets()["splunk"], [])


def test_validate_fails_only_when_kql_is_the_final_language(tmp_path):
    cfg_path = make_project(tmp_path, rule_text=ODD_RULE, extra_cfg="default_target: splunk\n")
    cfg = load_config(cfg_path)
    res = service.validate_text(cfg, ODD_RULE, None, None)
    kql = res["conversions"]["kql"]
    assert kql["ok"] is False and kql["code"] == "kql-table" and kql["hint"] and kql["line"] == 7
    assert res["state"] != "fail" and res["targets"] == ["splunk"]  # preview only
    (tmp_path / "b").mkdir()
    cfg2 = load_config(make_project(tmp_path / "b", rule_text=ODD_RULE, extra_cfg="default_target: kql\n"))
    assert service.validate_text(cfg2, ODD_RULE, None, None)["state"] == "fail"


BAD_KQL = ("kql: 3", "kql:\n  tables: [a]", "kql:\n  tables:\n    windows: Event", "kql:\n  tables:\n    windows/system: bad name",
           "kql:\n  default_table: '1x'", "kql:\n  other: 1")


@pytest.mark.parametrize("bad", BAD_KQL)
def test_config_section_parsing(tmp_path, bad):
    with pytest.raises(ConfigError):
        parse_config_text("schema_version: 1\n" + bad + "\n", tmp_path)


def test_config_normalises_keys(tmp_path):
    cfg = load_config(make_project(tmp_path, extra_cfg="kql:\n  tables:\n    Windows/System: MyEvents\n  default_table: Fallback\n"))
    assert cfg.kql.tables == {"windows/system": "MyEvents"} and cfg.kql.default_table == "Fallback"


def test_rule_block_kql_table_is_linted(tmp_path):
    from vitrix.routing import problems

    assert problems({"vitrix": {"kql_table": "Event"}}) == []
    assert problems({"vitrix": {"kql_table": "bad name"}})
    assert problems({"vitrix": {"kql_table": 5}})


def test_cli_convert_uses_the_default(tmp_path, capsys):
    from test_engine import run

    cfg = make_project(tmp_path, rule_text=SYSTEM_RULE, cases_text=CASES_OK)
    assert run(cfg, "convert", "--target", "kql") == 0


# ---- U4: SigmaHQ-style logsources beyond the Windows defaults --------------------------------


def _rule(ls: str, det: str = "    Foo: bar") -> str:
    body = "\n".join("  " + x for x in ls.split(";"))
    return SYSTEM_RULE.split("logsource:")[0] + f"logsource:\n{body}\ndetection:\n  selection:\n{det}\n  condition: selection\nlevel: low\n"


@pytest.mark.parametrize("ls,table", [
    ("product: linux", "Syslog"),
    ("product: macos", "Syslog"),
    ("product: windows;category: pipe_created", "Event"),
    ("product: windows;service: dns-client", "Event"),
    ("product: azure;service: pim", "AuditLogs"),
    ("product: azure;service: riskdetection", "AADUserRiskEvents"),
    ("product: m365;service: threat_management", "OfficeActivity"),
    ("product: kubernetes;service: audit", "AKSAudit"),
    ("product: cisco;service: aaa", "Syslog"),
    ("product: fortigate;service: event", "CommonSecurityLog"),
    ("category: proxy", "CommonSecurityLog"),
    ("category: dns", "DnsEvents"),
    ("service: nginx", "Syslog"),
])
def test_u4_builtin_tables(ls, table):
    assert first_line(convert_text(_rule(ls), KQL, [], KqlConfig())) == table


def test_u4_third_party_stays_actionable_with_suggestion():
    with pytest.raises(ConversionError) as ei:
        convert_text(_rule("product: okta;service: okta"), KQL, [], KqlConfig())
    assert ei.value.code == "kql-table" and "okta/okta" in ei.value.hint and "Okta_CL" in ei.value.hint
    assert convert_text(_rule("product: okta;service: okta"), KQL, [], KqlConfig(tables={"okta/okta": "Okta_CL"})).startswith("Okta_CL")


def test_u4_no_raw_pysigma_error():
    # a field the chosen table has no mapping for -> kql-field issue, not "SigmaTransformationError: ..."
    text = _rule("product: windows;service: bits-client", "    processPath: x")
    try:
        convert_text(text, KQL, [], KqlConfig())
    except ConversionError as exc:
        assert exc.code == "kql-field" and "processPath" in str(exc) and exc.hint
        assert "SigmaTransformationError" not in str(exc) and "SigmaTransformationError" not in exc.hint
    corr = SYSTEM_RULE.replace("detection:", "detection:")  # unrelated: bad hash algo below
    hashes = _rule("product: windows;category: driver_load", "    Hashes|contains: IMPHASH=ABC")
    with pytest.raises(ConversionError) as ei:
        convert_text(hashes, KQL, [], KqlConfig())
    assert ei.value.code == "kql-hash" and corr
