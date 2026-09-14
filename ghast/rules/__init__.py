"""Rule registry.

Rules are plain functions over a :class:`Context`.  Importing this package
registers the built-ins.
"""
from __future__ import annotations

from typing import Callable, Iterable, List

from ..findings import Finding
from .base import Context

RuleFn = Callable[[Context], Iterable[Finding]]
_RULES: List[RuleFn] = []


def rule(fn: RuleFn) -> RuleFn:
    _RULES.append(fn)
    return fn


def all_rules() -> List[RuleFn]:
    return list(_RULES)


def run_all(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for fn in _RULES:
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # noqa: BLE001
            ctx.errors.append("rule {} failed: {}: {}".format(
                getattr(fn, "__name__", "?"), exc.__class__.__name__, exc))
    return findings


from . import injection      # noqa: E402,F401
from . import privilege      # noqa: E402,F401
from . import supply_chain   # noqa: E402,F401
from . import runners        # noqa: E402,F401
