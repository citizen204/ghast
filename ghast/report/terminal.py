"""Human-readable output.

Each finding is printed as an argument: what the attacker controls, how it
travels, where it lands, and what that is worth.  A maintainer should be able to
act on it without opening the tool's source.
"""
from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional, Sequence

from ..findings import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding
from ..scan import ScanResult

_COLORS = {
    CRITICAL: "\033[1;97;41m",
    HIGH: "\033[1;31m",
    MEDIUM: "\033[1;33m",
    LOW: "\033[1;34m",
    INFO: "\033[1;90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"


def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return "{}{}{}".format(code, text, _RESET) if self.enabled else text

    def sev(self, severity: str) -> str:
        label = " {} ".format(severity.upper())
        return self(label, _COLORS[severity]) if self.enabled else "[{}]".format(severity.upper())


def _wrap(text: str, width: int, indent: str) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        candidate = word if not current else current + " " + word
        if len(candidate) + len(indent) > width:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines


def render_terminal(result: ScanResult, stream=None, width: int = 96,
                    show_flow: bool = True, explain: bool = False,
                    source_context: bool = True) -> str:
    stream = stream or sys.stdout
    style = _Style(_supports_color(stream))
    out: List[str] = []
    findings = result.sorted_findings()
    by_path: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_path.setdefault(finding.path, []).append(finding)

    sources = {w.path: w for w in result.workflows}

    for path, group in by_path.items():
        out.append("")
        out.append(style(path, _BOLD))
        out.append(style("─" * min(len(path), width), _DIM))
        for finding in group:
            out.append("")
            header = "{} {}  {}".format(
                style.sev(finding.severity),
                style("{}:{}".format(finding.rule_id, finding.line), _CYAN),
                style(finding.title, _BOLD),
            )
            out.append(header)
            meta_bits = []
            if finding.job:
                meta_bits.append("job `{}`".format(finding.job))
            if finding.step:
                meta_bits.append("step `{}`".format(finding.step))
            meta_bits.append("score {:.1f}".format(finding.score))
            if finding.occurrences > 1:
                meta_bits.append("{} occurrences in this file".format(finding.occurrences))
            out.append(style("      " + " · ".join(meta_bits), _DIM))
            out.extend(_wrap(finding.message, width, "      "))

            workflow = sources.get(finding.path)
            if source_context and workflow is not None:
                snippet = workflow.line_text(finding.line).rstrip()
                if snippet.strip():
                    out.append("")
                    out.append(style("      {:>5} │ ".format(finding.line), _DIM) + snippet.strip())
            elif finding.evidence:
                out.append("")
                out.append(style("        │ ", _DIM) + finding.evidence)

            if finding.occurrences > 1 and finding.other_lines:
                shown = list(finding.other_lines)[:6]
                suffix = ", ..." if len(finding.other_lines) > len(shown) else ""
                out.append(style("      also at line(s) {}{}".format(
                    ", ".join(str(n) for n in shown), suffix), _DIM))
                if finding.other_jobs:
                    jobs = list(finding.other_jobs)[:6]
                    more = " and {} more".format(len(finding.other_jobs) - len(jobs)) \
                        if len(finding.other_jobs) > len(jobs) else ""
                    out.append(style("      other jobs: {}{}".format(
                        ", ".join(jobs), more), _DIM))

            if show_flow and finding.flow:
                out.append("")
                out.append(style("      data flow:", _DIM))
                for index, hop in enumerate(finding.flow):
                    marker = "  ●" if index == 0 else "  ↓"
                    out.append(style("      {} {}".format(marker, hop), _DIM))

            if explain and finding.factors.notes:
                out.append("")
                out.append(style("      why this score:", _DIM))
                for note in finding.factors.notes:
                    out.extend(_wrap("- " + note, width, "        "))
                out.append(style("        " + finding.factors.explain(), _DIM))

            if finding.remediation:
                out.append("")
                out.append(style("      fix:", _DIM))
                for line in finding.remediation.splitlines():
                    if not line.strip():
                        out.append("")
                    elif line.startswith("    "):
                        out.append("        " + line)   # preserve code samples
                    else:
                        out.extend(_wrap(line, width, "        "))
            if finding.references:
                out.append(style("      ref: " + finding.references[0], _DIM))

    out.append("")
    out.append(_summary_line(result, style))
    for error in result.parse_errors:
        out.append(style("  ! could not parse " + error, _COLORS[MEDIUM] if False else _DIM))
    for error in result.rule_errors:
        out.append(style("  ! " + error, _DIM))
    return "\n".join(out) + "\n"


def _summary_line(result: ScanResult, style: "_Style") -> str:
    counts = result.counts()
    if not result.findings:
        return style("✓ {} file(s) scanned, nothing found".format(result.files_scanned), _BOLD)
    parts = []
    for severity in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        if counts.get(severity):
            parts.append(style("{} {}".format(counts[severity], severity), _COLORS[severity]))
    return "{} file(s) scanned · {}".format(result.files_scanned, "  ".join(parts))
