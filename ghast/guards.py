"""Recognising the ``if:`` conditions maintainers use as authorisation checks.

A privileged workflow that is gated on "the actor is a collaborator" is a very
different risk from one that is not.  Reporting both identically is how a
scanner gets muted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

STRONG = "strong"
WEAK = "weak"


@dataclass(frozen=True)
class Guard:
    strength: str
    description: str


_PATTERNS = (
    (
        re.compile(r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository"),
        STRONG,
        "restricted to pull requests from branches of this repository, not forks",
    ),
    (
        re.compile(r"github\.event\.pull_request\.head\.repo\.fork\s*==\s*false", re.I),
        STRONG,
        "restricted to non-fork pull requests",
    ),
    (
        re.compile(r"!\s*github\.event\.pull_request\.head\.repo\.fork"),
        STRONG,
        "restricted to non-fork pull requests",
    ),
    (
        re.compile(r"author_association\s*==\s*'(OWNER|MEMBER|COLLABORATOR)'"),
        STRONG,
        "restricted by author association",
    ),
    (
        re.compile(r"contains\(\s*fromJSON\([^)]*(OWNER|MEMBER|COLLABORATOR)[^)]*\)\s*,"
                   r"[^)]*author_association", re.I | re.S),
        STRONG,
        "restricted by author association allow-list",
    ),
    (
        re.compile(r"github\.actor\s*==\s*'[^']+'"),
        STRONG,
        "restricted to a named actor",
    ),
    (
        re.compile(r"contains\(\s*fromJSON\([^)]*\)\s*,\s*github\.actor\s*\)", re.I),
        STRONG,
        "restricted to an actor allow-list",
    ),
    (
        re.compile(r"github\.repository\s*==\s*'[^']+'"),
        STRONG,
        "restricted to a single repository (forks of this repo will not run it)",
    ),
    (
        re.compile(r"github\.repository_owner\s*==\s*'[^']+'"),
        STRONG,
        "restricted to a single repository owner",
    ),
    (
        re.compile(r"github\.event\.label\.name\s*==|contains\(\s*github\.event\.(pull_request\.)?labels?"
                   r"[^,]*,\s*'[^']+'\s*\)", re.I),
        WEAK,
        "gated on a label; labels survive subsequent pushes to the same pull request, "
        "so a maintainer who labels a benign diff also approves every later commit",
    ),
    (
        re.compile(r"github\.event\.review\.state\s*==\s*'approved'", re.I),
        WEAK,
        "gated on an approving review; approvals can be stale relative to the head commit",
    ),
)


def classify(condition: Optional[str]) -> List[Guard]:
    if not condition:
        return []
    text = str(condition)
    found: List[Guard] = []
    for pattern, strength, description in _PATTERNS:
        if pattern.search(text):
            found.append(Guard(strength, description))
    return found


def strongest(conditions: List[Optional[str]]) -> Optional[Guard]:
    best: Optional[Guard] = None
    for condition in conditions:
        for guard in classify(condition):
            if guard.strength == STRONG:
                return guard
            if best is None:
                best = guard
    return best
