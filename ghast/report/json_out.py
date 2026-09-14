"""Machine-readable output for pipelines and diffing between runs."""
from __future__ import annotations

import json
from typing import Any, Dict

from ..findings import RULES
from ..scan import ScanResult


def finding_to_dict(finding) -> Dict[str, Any]:
    return {
        "rule": finding.rule_id,
        "rule_name": RULES[finding.rule_id].name if finding.rule_id in RULES else None,
        "severity": finding.severity,
        "score": finding.score,
        "confidence": finding.factors.confidence,
        "attacker": finding.factors.actor,
        "guard": finding.factors.guard,
        "title": finding.title,
        "path": finding.path,
        "line": finding.line,
        "job": finding.job,
        "step": finding.step,
        "message": finding.message,
        "evidence": finding.evidence,
        "data_flow": list(finding.flow),
        "reasoning": list(finding.factors.notes),
        "score_breakdown": finding.factors.explain(),
        "remediation": finding.remediation,
        "references": list(finding.references),
        "tags": list(finding.tags),
        "fingerprint": finding.fingerprint(),
    }


def render_json(result: ScanResult, indent: int = 2) -> str:
    payload = {
        "tool": {"name": "ghast", "version": _version()},
        "summary": {
            "files_scanned": result.files_scanned,
            "findings": len(result.findings),
            "by_severity": result.counts(),
        },
        "findings": [finding_to_dict(f) for f in result.sorted_findings()],
        "errors": {
            "parse": result.parse_errors,
            "rules": result.rule_errors,
        },
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def _version() -> str:
    from .. import __version__
    return __version__
