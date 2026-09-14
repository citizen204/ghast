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


def test_a_repository_without_workflows_is_not_an_error():
    """`torvalds/linux` has no .github/workflows. That is an ordinary result,
    and reporting it as a parse failure teaches people to ignore the error
    list."""
    from ghast.hunt import NoWorkflows, RepoResult, summarise, to_scan_result

    results = [
        RepoResult(repo="a/has-ci", files=3),
        RepoResult(repo="b/no-ci", no_workflows=True),
        RepoResult(repo="c/broken", error="gh: rate limit exceeded"),
    ]
    assert results[1].status == "no workflows"
    assert issubclass(NoWorkflows, Exception)
    scan_result = to_scan_result(results)
    # Only the genuine failure is surfaced as an error.
    assert len(scan_result.parse_errors) == 1
    assert "c/broken" in scan_result.parse_errors[0]
    line = summarise(results)
    assert "1 repositories scanned" in line
    assert "1 use no GitHub Actions" in line
    assert "1 could not be read" in line


def test_rate_limiting_is_distinct_from_failure():
    """GitHub throttles burst concurrency separately from the hourly quota, so
    a scan can be blocked while `rate_limit` still reports 5000 remaining.
    Reporting that as "could not be read" sends people chasing the wrong
    problem."""
    from ghast.hunt import RateLimited, RepoResult, summarise, to_scan_result

    results = [
        RepoResult(repo="a/ok", files=4),
        RepoResult(repo="b/none", no_workflows=True),
        RepoResult(repo="c/throttled", rate_limited=True, error="HTTP 403 rate limit"),
        RepoResult(repo="d/broken", error="boom"),
    ]
    assert results[2].status == "rate limited — not scanned"
    line = summarise(results)
    assert "1 throttled by GitHub" in line
    assert "1 could not be read" in line

    scan_result = to_scan_result(results)
    joined = " ".join(scan_result.parse_errors)
    assert "d/broken" in joined
    assert "throttled the scan" in joined
    # The throttled repo is not listed as a per-repo failure.
    assert "c/throttled:" not in joined


def test_rate_limited_errors_are_classified_from_gh_output():
    import ghast.hunt as hunt

    for message in ("HTTP 403: API rate limit exceeded for user ID 1",
                    "You have exceeded a secondary rate limit",
                    "was submitted too quickly"):
        assert any(m in message.lower() for m in hunt._RATE_LIMIT_MARKERS), message
