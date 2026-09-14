import json
import os

import pytest

from ghast.cli import main

VULN = """
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
"""
SAFE = """
on: issues
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: echo "$T"
"""


def write_workflow(tmp_path, text, name="a.yml"):
    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(text)
    return str(tmp_path)


def test_exit_code_signals_findings(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN)
    assert main(["scan", root]) == 1
    assert "GHAST001" in capsys.readouterr().out


def test_clean_scan_exits_zero(tmp_path, capsys):
    root = write_workflow(tmp_path, SAFE)
    assert main(["scan", root]) == 0


def test_fail_on_never_always_exits_zero(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN)
    assert main(["scan", root, "--fail-on", "never"]) == 0


def test_skip_rule_suppresses_it(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN)
    assert main(["scan", root, "--skip", "GHAST001", "--fail-on", "high"]) == 0


def test_only_rule_filters(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN)
    main(["scan", root, "--only", "GHAST012", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in payload["findings"]} <= {"GHAST012"}


def test_output_file_is_written(tmp_path):
    root = write_workflow(tmp_path, VULN)
    target = tmp_path / "out" / "report.sarif"
    main(["scan", root, "--format", "sarif", "-o", str(target)])
    assert json.loads(target.read_text())["version"] == "2.1.0"


def test_missing_path_is_a_usage_error(capsys):
    assert main(["scan", "/definitely/not/here"]) == 2


def test_rules_listing(capsys):
    assert main(["rules"]) == 0
    assert "GHAST001" in capsys.readouterr().out


def test_explain_by_id_and_by_name(capsys):
    assert main(["explain", "ghast001"]) == 0
    assert "template-injection" in capsys.readouterr().out
    assert main(["explain", "pwn-request"]) == 0
    assert "GHAST010" in capsys.readouterr().out
    assert main(["explain", "nope"]) == 2


def test_malformed_yaml_is_reported_not_raised(tmp_path, capsys):
    root = write_workflow(tmp_path, "on: [push\njobs: {")
    assert main(["scan", root, "--fail-on", "never"]) == 0
    assert "could not parse" in capsys.readouterr().out


def test_exclude_skips_matching_paths(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN, "a.yml")
    fixtures = tmp_path / "examples" / "bad" / ".github" / "workflows"
    fixtures.mkdir(parents=True)
    (fixtures / "b.yml").write_text(VULN)

    main(["scan", root, "--format", "json"])
    both = json.loads(capsys.readouterr().out)
    assert both["summary"]["files_scanned"] == 2

    main(["scan", root, "--format", "json", "--exclude", "*/examples/*"])
    filtered = json.loads(capsys.readouterr().out)
    assert filtered["summary"]["files_scanned"] == 1


def test_exclude_accepts_a_bare_directory_name(tmp_path, capsys):
    root = write_workflow(tmp_path, VULN, "a.yml")
    fixtures = tmp_path / "examples" / ".github" / "workflows"
    fixtures.mkdir(parents=True)
    (fixtures / "b.yml").write_text(VULN)
    main(["scan", root, "--format", "json", "--exclude", "examples"])
    assert json.loads(capsys.readouterr().out)["summary"]["files_scanned"] == 1
