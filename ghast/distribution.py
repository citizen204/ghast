"""How a sweep's findings are distributed across rules.

This module exists because of a bug it would have caught.

GHAST023 once claimed that a plain ``actions/cache`` step in fork CI could
poison the default branch's cache.  That is false — GitHub scopes a pull
request's caches to ``refs/pull/N/merge`` — and the rule fired on 59 of the 61
medium-severity findings in a 67-repository sweep.  Every test passed, before
and after, because the tests encoded the same wrong belief the code did.

What gave it away was the ratio.  No rule is 97% of a severity band; a rule
that common is describing something normal and calling it dangerous.  Nothing
in the tool said so out loud, so noticing it was luck.

So the tool now says it out loud.  This is not a correctness check and it
cannot be: a rule may legitimately dominate a band if the mistake it detects is
genuinely widespread, and a wrong rule that fires twice will not show up here
at all.  It reports a shape, and says which rule to go and re-read.
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, NamedTuple, Optional, Sequence

from .findings import Finding

#: A rule holding at least this share of a band is worth re-reading.
DOMINANCE = 0.60

#: Below this many findings in a band, the share means nothing — one rule
#: firing twice out of three is not a distribution.
MIN_BAND = 8

#: Bands worth checking.  "critical" is excluded on purpose: a sweep that
#: produces enough criticals for a ratio to be meaningful has a different
#: problem, and the band is usually too small for this to say anything.
BANDS = ("high", "medium", "low")


class RuleShare(NamedTuple):
    rule_id: str
    count: int
    share: float


class BandReport(NamedTuple):
    band: str
    total: int
    rules: List[RuleShare]
    repos: int

    @property
    def leader(self) -> Optional[RuleShare]:
        return self.rules[0] if self.rules else None

    @property
    def is_concentrated(self) -> bool:
        top = self.leader
        return (top is not None
                and self.total >= MIN_BAND
                and top.share >= DOMINANCE)


def _repo_of(finding: Finding) -> str:
    """The repository a finding came from, if the path carries one.

    ``hunt`` writes paths as ``owner/repo/.github/workflows/x.yml``; a local
    scan writes a plain relative path and contributes a single bucket.
    """
    parts = finding.path.split("/")
    if len(parts) >= 3 and parts[2] == ".github":
        return "/".join(parts[:2])
    return "."


def band_report(findings: Sequence[Finding], band: str) -> BandReport:
    in_band = [f for f in findings if f.severity == band]
    counts = Counter(f.rule_id for f in in_band)
    total = len(in_band)
    rules = [RuleShare(rule_id, n, n / total if total else 0.0)
             for rule_id, n in counts.most_common()]
    return BandReport(band=band, total=total, rules=rules,
                      repos=len({_repo_of(f) for f in in_band}))


def report(findings: Sequence[Finding]) -> Dict[str, BandReport]:
    return {band: band_report(findings, band) for band in BANDS}


def concentrated(findings: Sequence[Finding]) -> List[BandReport]:
    """Bands where one rule accounts for most of the findings."""
    return [r for r in report(findings).values() if r.is_concentrated]


def render(findings: Sequence[Finding], show_all: bool = False) -> str:
    """The distribution, as lines for a terminal.  Empty when there is
    nothing worth saying and ``show_all`` is off."""
    reports = report(findings)
    flagged = [r for r in reports.values() if r.is_concentrated]
    if not flagged and not show_all:
        return ""

    lines: List[str] = []
    shown = reports.values() if show_all else flagged
    for rep in shown:
        if not rep.total:
            continue
        lines.append("{} severity — {} finding{} across {} repositor{}".format(
            rep.band, rep.total, "" if rep.total == 1 else "s",
            rep.repos, "y" if rep.repos == 1 else "ies"))
        for share in rep.rules[:4]:
            lines.append("  {:<10} {:>4}  {:>4.0%}{}".format(
                share.rule_id, share.count, share.share,
                "  <-- dominates this band" if (
                    rep.is_concentrated and share is rep.leader) else ""))
        if len(rep.rules) > 4:
            lines.append("  {:<10} {:>4}".format(
                "(others)", sum(s.count for s in rep.rules[4:])))
        lines.append("")

    if flagged:
        names = ", ".join(sorted({r.leader.rule_id for r in flagged if r.leader}))
        lines.append(
            "One rule holding most of a severity band usually means the rule is "
            "describing something normal, not something rare. Re-read what {} "
            "claims against the platform's documentation before trusting these "
            "findings. This is a shape, not a verdict — a widespread real mistake "
            "looks the same.".format(names))
    return "\n".join(lines).rstrip("\n")
