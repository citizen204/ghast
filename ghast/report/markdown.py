"""Markdown output, for PR comments and job summaries."""
from __future__ import annotations

from typing import Dict, List

from ..findings import CRITICAL, HIGH, INFO, LOW, MEDIUM, Finding
from ..scan import ScanResult

_ICON = {CRITICAL: "🟥", HIGH: "🟧", MEDIUM: "🟨", LOW: "🟦", INFO: "⬜"}


def render_markdown(result: ScanResult, title: str = "ghast: GitHub Actions security scan",
                    max_detail: int = 25) -> str:
    lines: List[str] = ["## {}".format(title), ""]
    counts = result.counts()
    if not result.findings:
        lines.append("Scanned **{}** workflow file(s). No findings.".format(result.files_scanned))
        return "\n".join(lines) + "\n"

    summary = " · ".join(
        "{} **{}** {}".format(_ICON[s], counts[s], s)
        for s in (CRITICAL, HIGH, MEDIUM, LOW, INFO) if counts.get(s)
    )
    lines.append("Scanned **{}** workflow file(s) — {}".format(result.files_scanned, summary))
    lines.append("")
    lines.append("| | Rule | Location | Finding | Score |")
    lines.append("|---|---|---|---|---|")
    for finding in result.sorted_findings():
        title = finding.title.replace("|", "\\|")
        if finding.occurrences > 1:
            title += " _(x{})_".format(finding.occurrences)
        lines.append("| {} | `{}` | `{}:{}` | {} | {:.1f} |".format(
            _ICON[finding.severity], finding.rule_id, finding.path, finding.line,
            title, finding.score))
    lines.append("")

    for finding in result.sorted_findings()[:max_detail]:
        lines.append("<details>")
        lines.append("<summary>{} <code>{}</code> {} — <code>{}:{}</code></summary>".format(
            _ICON[finding.severity], finding.rule_id,
            finding.title.replace("<", "&lt;"), finding.path, finding.line))
        lines.append("")
        lines.append(finding.message)
        lines.append("")
        if finding.evidence:
            lines.append("```yaml")
            lines.append(finding.evidence)
            lines.append("```")
            lines.append("")
        if finding.flow:
            lines.append("**Data flow**")
            lines.append("")
            for index, hop in enumerate(finding.flow):
                lines.append("{}. {}".format(index + 1, hop))
            lines.append("")
        if finding.factors.notes:
            lines.append("**Why this severity**")
            lines.append("")
            for note in finding.factors.notes:
                lines.append("- {}".format(note))
            lines.append("")
            lines.append("`{}`".format(finding.factors.explain()))
            lines.append("")
        if finding.remediation:
            lines.append("**Fix**")
            lines.append("")
            lines.append(finding.remediation)
            lines.append("")
        if finding.references:
            lines.append("Reference: <{}>".format(finding.references[0]))
            lines.append("")
        lines.append("</details>")
        lines.append("")
    return "\n".join(lines) + "\n"
