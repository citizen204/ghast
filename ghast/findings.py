"""Findings, and the scoring model that ranks them.

A severity label is only useful if it survives contact with a maintainer.  The
score here is deliberately explainable: impact of the sink, discounted by how
privileged the attacker must be, by any authorisation guard on the job, and by
how confident the analysis is.  Every finding carries the factors that produced
its score so a reviewer can argue with it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# Impact of a successful exploit, on a 0-10 scale.
IMPACT_SECRETS_AND_WRITE = 10.0   # repo secrets + a write-scoped GITHUB_TOKEN
IMPACT_SECRETS = 8.5              # secrets, token constrained
IMPACT_WRITE_TOKEN = 8.0          # write token, no other secrets
IMPACT_RUNNER = 6.0               # code execution on the runner only
IMPACT_PERSISTENCE = 9.0          # self-hosted runner: persistence beyond the job
IMPACT_ARGUMENT = 3.5             # attacker appends flags to a command
IMPACT_HYGIENE = 2.5              # no direct exploit path; weakens the posture

# Multipliers.
ACTOR_MULTIPLIER = {
    "any-github-user": 1.0,
    "any-user-after-approval": 0.7,
    "write-access": 0.35,
}
GUARD_MULTIPLIER = {None: 1.0, "weak": 0.8, "strong": 0.3}
CONFIDENCE_MULTIPLIER = {"certain": 1.0, "likely": 0.8, "speculative": 0.6}


@dataclass
class ScoreFactors:
    impact: float
    actor: str
    guard: Optional[str] = None
    confidence: str = "certain"
    notes: List[str] = field(default_factory=list)

    def score(self) -> float:
        value = self.impact
        value *= ACTOR_MULTIPLIER.get(self.actor, 0.35)
        value *= GUARD_MULTIPLIER.get(self.guard, 1.0)
        value *= CONFIDENCE_MULTIPLIER.get(self.confidence, 1.0)
        return round(min(value, 10.0), 1)

    def explain(self) -> str:
        parts = [
            "impact {:.1f}".format(self.impact),
            "attacker {} (x{:.2f})".format(self.actor, ACTOR_MULTIPLIER.get(self.actor, 0.35)),
        ]
        if self.guard:
            parts.append("guard {} (x{:.2f})".format(self.guard, GUARD_MULTIPLIER[self.guard]))
        if self.confidence != "certain":
            parts.append("confidence {} (x{:.2f})".format(
                self.confidence, CONFIDENCE_MULTIPLIER.get(self.confidence, 1.0)))
        return " x ".join(parts) + " = {:.1f}".format(self.score())


def severity_for(score: float) -> str:
    if score >= 9.0:
        return CRITICAL
    if score >= 7.0:
        return HIGH
    if score >= 4.0:
        return MEDIUM
    if score >= 2.0:
        return LOW
    return INFO


@dataclass
class Finding:
    rule_id: str
    title: str
    path: str
    line: int
    message: str
    factors: ScoreFactors
    col: int = 1
    end_line: Optional[int] = None
    job: Optional[str] = None
    step: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    flow: Sequence[str] = ()
    references: Sequence[str] = ()
    tags: Sequence[str] = ()
    fingerprint_extra: str = ""
    #: Set when identical findings elsewhere in the same file were folded in.
    occurrences: int = 1
    other_jobs: Sequence[str] = ()
    other_lines: Sequence[int] = ()

    @property
    def score(self) -> float:
        return self.factors.score()

    @property
    def severity(self) -> str:
        return severity_for(self.score)

    @property
    def location(self) -> str:
        return "{}:{}".format(self.path, self.line)

    def fingerprint(self) -> str:
        """Stable across line moves so CI can diff findings between runs."""
        import hashlib

        basis = "|".join(
            [self.rule_id, self.path, self.job or "", self.step or "",
             self.evidence.strip(), self.fingerprint_extra]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def sort_key(self) -> Tuple[float, str, int]:
        return (-self.score, self.path, self.line)


@dataclass
class RuleMeta:
    id: str
    name: str
    summary: str
    description: str
    remediation: str
    references: Sequence[str] = ()
    tags: Sequence[str] = ()


RULES: Dict[str, RuleMeta] = {}


def register(meta: RuleMeta) -> RuleMeta:
    RULES[meta.id] = meta
    return meta


def sentence(text: str, index: int = 0) -> str:
    """One sentence from a rule description, normalised to end with a period."""
    parts = [p.strip() for p in text.split(". ") if p.strip()]
    if index >= len(parts):
        index = len(parts) - 1
    chosen = parts[index].rstrip(".")
    return chosen + "."
