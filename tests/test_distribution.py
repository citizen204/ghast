"""The distribution report.

The rule this module exists for is GHAST023, which once produced 59 of 61
medium findings while claiming something false about GitHub's cache scoping.
The first test below rebuilds that shape.  It is the only regression test in
this suite that asserts on a *ratio* rather than on an analysis result,
because the ratio is what the tests of the day could not see.
"""
from ghast import distribution
from ghast.findings import Finding, ScoreFactors


def _finding(rule_id: str, repo: str, n: int, impact: float = 5.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="synthetic",
        path="{}/.github/workflows/ci-{}.yml".format(repo, n),
        line=n,
        message="synthetic finding for distribution tests",
        factors=ScoreFactors(impact=impact, actor="any-github-user"),
    )


def _sweep(spec):
    """spec: {rule_id: (count, impact)} spread over distinct repositories."""
    out = []
    n = 0
    for rule_id, (count, impact) in spec.items():
        for _ in range(count):
            out.append(_finding(rule_id, "owner{}/repo{}".format(n % 67, n % 67), n, impact))
            n += 1
    return out


def test_the_shape_that_caught_ghast023():
    # 59 of 61 medium findings from one rule, across a 67-repository sweep.
    findings = _sweep({"GHAST023": (59, 5.0), "GHAST020": (2, 5.0)})
    assert all(f.severity == "medium" for f in findings)

    flagged = distribution.concentrated(findings)
    assert [r.band for r in flagged] == ["medium"]

    report = flagged[0]
    assert report.total == 61
    assert report.leader.rule_id == "GHAST023"
    assert report.leader.count == 59
    assert round(report.leader.share, 2) == 0.97

    text = distribution.render(findings)
    assert "GHAST023" in text
    assert "dominates this band" in text
    # It must not claim the rule is wrong -- only that the shape is worth a look.
    assert "shape, not a verdict" in text


def test_an_even_spread_says_nothing():
    findings = _sweep({
        "GHAST001": (9, 5.0), "GHAST010": (8, 5.0),
        "GHAST020": (7, 5.0), "GHAST030": (6, 5.0),
    })
    assert distribution.concentrated(findings) == []
    assert distribution.render(findings) == ""


def test_a_small_band_is_not_a_distribution():
    # One rule, 100% of the band -- but three findings is not evidence of anything.
    findings = _sweep({"GHAST001": (3, 5.0)})
    assert distribution.concentrated(findings) == []


def test_show_all_prints_even_when_nothing_is_flagged():
    findings = _sweep({"GHAST001": (5, 5.0), "GHAST010": (5, 5.0)})
    text = distribution.render(findings, show_all=True)
    assert "GHAST001" in text and "GHAST010" in text
    assert "dominates this band" not in text


def test_bands_are_counted_separately():
    findings = _sweep({"GHAST001": (20, 8.0), "GHAST020": (10, 5.0),
                       "GHAST021": (10, 5.0)})
    report = distribution.report(findings)
    assert report["high"].total == 20
    assert report["medium"].total == 20
    assert report["high"].is_concentrated is True
    assert report["medium"].is_concentrated is False


def test_repository_count_comes_from_the_path():
    findings = [_finding("GHAST001", "a/b", 1), _finding("GHAST001", "a/b", 2),
                _finding("GHAST001", "c/d", 3)]
    assert distribution.band_report(findings, "medium").repos == 2


def test_a_local_scan_path_does_not_pretend_to_be_a_repository():
    local = Finding(
        rule_id="GHAST001", title="t", path=".github/workflows/ci.yml", line=1,
        message="m", factors=ScoreFactors(impact=5.0, actor="any-github-user"))
    assert distribution.band_report([local], "medium").repos == 1
