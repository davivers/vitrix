"""B3: issues say WHERE (path, line, column) and HOW to fix (hint)."""

from __future__ import annotations

import yaml
from test_engine import CASES_OK, RULE_OK, make_project

from vitrix import cases as cases_mod
from vitrix import service
from vitrix.config import load_config
from vitrix.lint import Issue, Locator, lint_doc, lint_files
from vitrix.loader import RuleFile

BAD = """\
title: x
id: nope
status: tst
level: urgent
logsource: {product: windows}
tags: [attack.t9999, attack.exection, 'ATTACK.bad tag']
falsepositives: none
date: yesterday
detection:
  selection:
    Image|endswithh: a
    CommandLine|re: '(a'
  unused:
    Foo: 1
  condition: selecton
vitrix:
  owner: ''
  target: nonsuch
  bogus: 1
descripton: typo
"""


def lint_text(text: str, targets=None) -> list[Issue]:
    docs = [d for d in yaml.safe_load_all(text) if d is not None]
    locs = Locator.for_text(text)
    out: list[Issue] = []
    for doc, loc in zip(docs, locs, strict=True):
        out += lint_doc(doc, "r.yml", targets or {"splunk", "kql"}, loc)
    return out


def by_code(issues):
    d = {}
    for i in issues:
        d.setdefault(i.code, []).append(i)
    return d


def test_every_issue_has_code_hint_and_a_line():
    issues = lint_text(BAD)
    assert issues
    for i in issues:
        assert i.code and i.hint and i.line and i.column, i
        assert i.to_dict()["severity"] == i.severity and "fix" in i.to_dict()
    codes = by_code(issues)
    for expected in ("invalid-uuid", "invalid-status", "invalid-level", "bad-modifier", "bad-regex", "unknown-selection", "unused-selection",
                     "unknown-technique", "unknown-tactic", "bad-list-field", "bad-date", "unknown-field", "unknown-target",
                     "bad-vitrix-block", "bad-governance", "missing-field"):
        assert expected in codes, expected


def test_nested_detection_locations():
    codes = by_code(lint_text(BAD))
    mod = codes["bad-modifier"][0]
    assert (mod.line, mod.column) == (11, 5) and mod.path == "detection.selection.Image|endswithh"
    assert "Image|endswith" in mod.hint and mod.fix["snippet"] == "Image|endswith"
    rx = codes["bad-regex"][0]
    assert rx.line == 12 and rx.column == 21 and "position" in rx.hint  # the VALUE node, not the key
    assert (codes["unknown-selection"][0].line, {i.path: i.line for i in codes["unused-selection"]}["detection.unused"]) == (15, 13)
    assert "selection" in codes["unknown-selection"][0].hint
    assert codes["invalid-uuid"][0].line == 2 and "-" in codes["invalid-uuid"][0].fix["snippet"]
    assert codes["unknown-target"][0].path == "vitrix.target" and "splunk" in codes["unknown-target"][0].hint
    assert any(i.path == "vitrix.owner" and i.line == 17 for i in codes["bad-governance"])


def test_attack_tags_point_at_the_tag_and_suggest_neighbours():
    codes = by_code(lint_text(BAD))
    tech = codes["unknown-technique"][0]
    assert tech.path == "tags.0" and "attack.t" in tech.hint and tech.fix["snippet"].startswith("attack.t")
    tactic = codes["unknown-tactic"][0]
    assert "attack.execution" in tactic.hint and tactic.path == "tags.1"


def test_missing_field_points_at_the_document_and_offers_a_snippet():
    issues = lint_text("description: d\n")
    miss = {i.path: i for i in issues if i.code == "missing-field"}
    assert miss["title"].fix["snippet"].startswith("title:") and miss["id"].fix["snippet"].startswith("id: ")
    assert miss["title"].line == 1
    assert {"detection", "logsource"} & {i.path for i in issues}


def test_list_selection_and_condition_codes():
    head = "title: t\nid: 11111111-1111-4111-8111-111111111111\nlogsource: {product: windows}\ndetection:\n"
    mod = by_code(lint_text(head + "  selection:\n    - Image|bad: a\n    - CommandLine: b\n  condition: selection\n"))["bad-modifier"][0]
    assert mod.line == 6 and mod.hint
    no_cond = by_code(lint_text(head + "  sel: {A: 1}\n"))
    assert no_cond["missing-condition"][0].fix["snippet"] == "condition: sel"
    pat = by_code(lint_text(head + "  sel: {A: 1}\n  condition: 1 of zzz*\n"))
    assert "pattern-no-match" in pat and pat["pattern-no-match"][0].hint


def test_regex_backtracking_and_complexity_have_hints():
    text = "title: t\ndetection:\n  sel:\n    A|re: '(a+)+b'\n  condition: sel\n"
    assert by_code(lint_text(text))["regex-backtracking"][0].hint
    many = "title: t\ndetection:\n  sel:\n    A|contains:\n" + "".join(f"      - v{i}\n" for i in range(60)) + "  condition: sel\n"
    assert by_code(lint_text(many))["complex-rule"][0].hint


def test_duplicate_id_and_logic_and_empty_file(tmp_path):
    a = RuleFile(tmp_path / "a.yml", "a.yml", RULE_OK, list(yaml.safe_load_all(RULE_OK)))
    b = RuleFile(tmp_path / "b.yml", "b.yml", RULE_OK, list(yaml.safe_load_all(RULE_OK)))
    e = RuleFile(tmp_path / "e.yml", "e.yml", "", [])
    codes = by_code(lint_files([a, b, e]))
    dup = codes["duplicate-id"][0]
    assert dup.rule == "b.yml" and dup.line == 2 and "a.yml" in dup.hint and "id:" in dup.fix["snippet"]
    assert codes["duplicate-logic"][0].hint and codes["empty-file"][0].hint


def test_invalid_yaml_is_located(tmp_path):
    out = service.validate_text(load_config(make_project(tmp_path)), "title: x\nbad: [unclosed\n")
    issue = out["lint"][0]
    assert issue["code"] == "invalid-yaml" and issue["line"] and issue["hint"]
    assert set(issue) >= {"severity", "rule", "message", "code", "path", "line", "column", "hint", "fix"}


def test_validate_response_keeps_old_fields_and_adds_new(tmp_path):
    cfg = load_config(make_project(tmp_path))
    text = RULE_OK.replace("level: medium", "level: urgent")
    lint = service.validate_text(cfg, text, CASES_OK)["lint"]
    assert lint and all({"severity", "message", "code", "hint", "line", "column", "path"} <= set(i) for i in lint)
    assert next(i for i in lint if i["code"] == "invalid-level")["line"] == text.splitlines().index("level: urgent") + 1


def test_case_failures_explain_which_field_and_why(tmp_path):
    cfg = load_config(make_project(tmp_path))
    cases = ("cases:\n  - name: pos\n    expect: match\n    event: {Image: 'C:\\\\x\\\\tool.exe', CommandLine: 'tool.exe --ok'}\n"
             "  - name: neg\n    expect: no_match\n    event: {Image: 'C:\\\\x\\\\tool.exe', CommandLine: 'tool.exe --bad'}\n")
    out = service.validate_text(cfg, RULE_OK, cases)
    res = {r["name"]: r for r in out["tests"]["results"]}
    assert not res["pos"]["passed"] and "CommandLine" in res["pos"]["hint"] and "--bad" in res["pos"]["hint"]
    assert not res["neg"]["passed"] and "selection" in res["neg"]["hint"] and "no match" in res["neg"]["hint"]
    missing = service.validate_text(cfg, RULE_OK, "cases:\n  - name: m\n    expect: match\n    event: {Other: 1}\n")
    assert "missing from the event" in missing["tests"]["results"][0]["hint"]


def test_case_file_problems_are_located_in_the_cases_file():
    cases, problems = cases_mod.parse_cases(
        "cases:\n  - name: a\n    expect: maybe\n    event: {A: 1}\n  - name: b\n    expect: match\n    kind: nope\n    event: {A: 2}\n"
        "  - name: c\n    expect: match\n    event: {A: 3}\n  - name: d\n    expect: match\n    event: {A: 3}\n", "cases", "r.yml")
    assert len(cases) == 2
    codes = by_code(problems)
    assert codes["case-bad-expect"][0].line == 3 and codes["case-bad-expect"][0].file == "cases"
    assert codes["case-bad-kind"][0].line == 7
    assert codes["case-duplicate-event"][0].line == 14 and all(p.hint for p in problems)
    _, bad = cases_mod.parse_cases("cases: [", "cases", "r.yml")
    assert bad[0].code == "cases-invalid-yaml" and bad[0].line and bad[0].hint
    _, none = cases_mod.parse_cases("x: 1\n", "cases", "r.yml")
    assert none[0].code == "cases-missing" and none[0].hint


def test_non_mapping_document_has_a_hint():
    issues = lint_doc(["a", "b"], "r.yml", None, Locator.for_text("- a\n- b\n")[0])
    assert issues[0].code == "not-a-mapping" and issues[0].hint and issues[0].line == 1


def test_cli_prints_location_and_hint(capsys):
    from vitrix.cli import print_issues

    print_issues([Issue("error", "r.yml", "boom", "x", "a.b", 3, 7, "do this")])
    out = capsys.readouterr().out
    assert "error: boom  [3:7]" in out and "hint: do this" in out
    assert str(Issue("error", "r.yml", "boom")) == "error: boom"
