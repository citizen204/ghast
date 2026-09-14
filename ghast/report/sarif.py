"""SARIF 2.1.0 output.

This is what makes the tool usable rather than merely correct: uploading SARIF
to `github/codeql-action/upload-sarif` puts every finding in the Security tab
and as an inline annotation on the pull request that introduced it.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ..findings import CRITICAL, HIGH, INFO, LOW, MEDIUM, RULES
from ..scan import ScanResult

_SARIF_LEVEL = {CRITICAL: "error", HIGH: "error", MEDIUM: "warning",
                LOW: "note", INFO: "note"}
# GitHub ranks findings by security-severity; these mirror the score bands.
_SECURITY_SEVERITY = {CRITICAL: "9.5", HIGH: "7.5", MEDIUM: "5.0",
                      LOW: "3.0", INFO: "1.0"}


def _rule_descriptor(rule_id: str) -> Dict[str, Any]:
    meta = RULES[rule_id]
    return {
        "id": meta.id,
        "name": "".join(part.capitalize() for part in meta.name.split("-")),
        "shortDescription": {"text": meta.summary},
        "fullDescription": {"text": meta.description},
        "help": {
            "text": meta.description + "\n\nRemediation:\n" + meta.remediation,
            "markdown": "{}\n\n**Remediation**\n\n{}\n\n{}".format(
                meta.description,
                meta.remediation,
                "\n".join("- <{}>".format(r) for r in meta.references),
            ),
        },
        "properties": {
            "tags": ["security"] + list(meta.tags),
            "precision": "high",
        },
        "helpUri": meta.references[0] if meta.references else
                   "https://github.com/USERNAME/ghast#rules",
    }


def render_sarif(result: ScanResult, indent: int = 2) -> str:
    from .. import __version__

    used: List[str] = []
    for finding in result.sorted_findings():
        if finding.rule_id in RULES and finding.rule_id not in used:
            used.append(finding.rule_id)

    results: List[Dict[str, Any]] = []
    for finding in result.sorted_findings():
        if finding.rule_id not in RULES:
            continue
        message = finding.message
        if finding.flow:
            message += "\n\nData flow: " + " -> ".join(finding.flow)
        results.append({
            "ruleId": finding.rule_id,
            "ruleIndex": used.index(finding.rule_id),
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/"),
                                         "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(finding.line, 1),
                               "startColumn": max(finding.col, 1)},
                }
            }],
            "partialFingerprints": {"ghastFingerprint/v1": finding.fingerprint()},
            "properties": {
                "score": finding.score,
                "attacker": finding.factors.actor,
                "security-severity": _SECURITY_SEVERITY[finding.severity],
                "reasoning": list(finding.factors.notes),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ghast",
                "version": __version__,
                "informationUri": "https://github.com/USERNAME/ghast",
                "rules": [_rule_descriptor(r) for r in used],
            }},
            "results": results,
            "columnKind": "utf16CodeUnits",
        }],
    }
    return json.dumps(sarif, indent=indent, ensure_ascii=False)
