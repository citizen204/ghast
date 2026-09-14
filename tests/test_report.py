import json

from ghast import scan
from ghast.report import render_json, render_markdown, render_sarif, render_terminal
from helpers import analyse


def build_result(text="""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
"""):
    from ghast import model, taint
    from ghast.rules import Context, run_all

    workflow = model.parse_text(text, ".github/workflows/a.yml")
    engine = taint.analyse(workflow)
    result = scan.ScanResult()
    result.files_scanned = 1
    result.workflows.append(workflow)
    result.findings.extend(run_all(Context(workflow=workflow, engine=engine)))
    return result


def test_json_round_trips():
    payload = json.loads(render_json(build_result()))
    assert payload["summary"]["findings"] == len(payload["findings"])
    top = payload["findings"][0]
    assert top["rule"] == "GHAST001"
    assert top["severity"] == "critical"
    assert top["data_flow"]
    assert top["fingerprint"]


def test_sarif_is_well_formed():
    sarif = json.loads(render_sarif(build_result()))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert rules and all("id" in r and "help" in r for r in rules)
    for result in run["results"]:
        assert result["ruleIndex"] < len(rules)
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert result["properties"]["security-severity"]


def test_markdown_has_a_table_and_details():
    text = render_markdown(build_result())
    assert "| Rule |" in text
    assert "<details>" in text
    assert "GHAST001" in text


def test_terminal_output_is_plain_without_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    text = render_terminal(build_result())
    assert "\033[" not in text
    assert "GHAST001" in text


def test_fingerprints_are_stable_across_line_moves():
    a = build_result()
    b = build_result("\n\n\n" + """
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
""")
    assert a.findings[0].fingerprint() == b.findings[0].fingerprint()
