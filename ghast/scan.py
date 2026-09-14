"""Discovery and orchestration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

from . import model, taint
from .findings import Finding, SEVERITY_ORDER
from .rules import Context, run_all

WORKFLOW_DIR = os.path.join(".github", "workflows")
_YAML_EXT = (".yml", ".yaml")
_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
              "dist", "build", ".tox", ".mypy_cache", "target"}


def build_index(workflows: Iterable[model.Workflow]) -> Dict[str, Set[str]]:
    """Map each workflow's declared `name:` to the events that start it.

    `on: workflow_run: workflows: ["Build"]` names its upstream by display
    name, so answering "can an outsider cause this workflow to run?" means
    looking at a *different file*.  Without this, every `workflow_run` has to
    be assumed outsider-reachable, which is the safe default but turns
    push-only deployment pipelines into false criticals.
    """
    index: Dict[str, Set[str]] = {}
    for workflow in workflows:
        if workflow.kind != "workflow" or not workflow.name:
            continue
        index.setdefault(workflow.name.strip(), set()).update(workflow.event_names)
    return index


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    parse_errors: List[str] = field(default_factory=list)
    rule_errors: List[str] = field(default_factory=list)
    workflows: List[model.Workflow] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def worst_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


def _excluded(path: str, patterns: Sequence[str]) -> bool:
    import fnmatch

    normalised = path.replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(normalised, pattern):
            return True
        # A bare directory name should exclude everything under it.
        if "/" not in pattern and "*" not in pattern:
            if pattern in normalised.split("/"):
                return True
        if fnmatch.fnmatch(normalised, pattern.rstrip("/") + "/*"):
            return True
    return False


def discover(root: str, include_actions: bool = True,
             exclude: Sequence[str] = ()) -> List[str]:
    """Workflow (and optionally composite-action) files under ``root``."""
    if os.path.isfile(root):
        return [] if _excluded(root, exclude) else [root]
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        if exclude and _excluded(dirpath, exclude):
            dirnames[:] = []
            continue
        normalised = dirpath.replace("\\", "/")
        in_workflow_dir = normalised.endswith(".github/workflows")
        for name in sorted(filenames):
            if not name.endswith(_YAML_EXT):
                continue
            full = os.path.join(dirpath, name)
            if exclude and _excluded(full, exclude):
                continue
            if in_workflow_dir:
                found.append(full)
            elif include_actions and name in ("action.yml", "action.yaml"):
                found.append(full)
    return found


def analyse_workflow(workflow: model.Workflow,
                     index: Optional[Dict[str, Set[str]]] = None) -> ScanResult:
    result = ScanResult()
    result.files_scanned = 1
    result.workflows.append(workflow)
    if workflow.parse_error:
        result.parse_errors.append("{}: {}".format(workflow.path, workflow.parse_error))
        return result
    if workflow.kind == "workflow" and not workflow.jobs:
        return result
    engine = taint.analyse(workflow)
    ctx = Context(workflow=workflow, engine=engine, index=index or {})
    result.findings.extend(run_all(ctx))
    result.rule_errors.extend(ctx.errors)
    return result


def scan_file(path: str, display_path: Optional[str] = None,
              index: Optional[Dict[str, Set[str]]] = None) -> ScanResult:
    try:
        workflow = model.parse_file(path)
    except OSError as exc:
        result = ScanResult()
        result.parse_errors.append("{}: {}".format(path, exc))
        return result
    if display_path:
        workflow.path = display_path
    return analyse_workflow(workflow, index)


def scan_paths(paths: Sequence[str], include_actions: bool = True,
               relative_to: Optional[str] = None,
               exclude: Sequence[str] = ()) -> ScanResult:
    combined = ScanResult()
    seen: Set[str] = set()

    # Two passes: everything is parsed before anything is analysed, so that a
    # rule can ask about a workflow other than the one it is looking at.
    parsed: List[model.Workflow] = []
    for root in paths:
        for path in discover(root, include_actions=include_actions, exclude=exclude):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            display = path
            if relative_to:
                try:
                    display = os.path.relpath(path, relative_to)
                except ValueError:
                    pass
            try:
                workflow = model.parse_file(path)
            except OSError as exc:
                combined.parse_errors.append("{}: {}".format(path, exc))
                continue
            workflow.path = display
            parsed.append(workflow)

    index = build_index(parsed)
    for workflow in parsed:
        single = analyse_workflow(workflow, index)
        combined.findings.extend(single.findings)
        combined.files_scanned += single.files_scanned
        combined.parse_errors.extend(single.parse_errors)
        combined.rule_errors.extend(single.rule_errors)
        combined.workflows.extend(single.workflows)
    return combined


def collapse(findings: Iterable[Finding]) -> List[Finding]:
    """Fold repeats of the same finding within one file into a single entry.

    A generated workflow with 170 jobs that all run on the same self-hosted
    runner is one decision, made once.  Printing it 170 times does not tell the
    reader anything the first line did not, and it buries everything else in
    the report.  Machine-readable output keeps every occurrence; this is for
    the formats a person reads.
    """
    import copy

    groups: Dict[Tuple[str, str, str], Finding] = {}
    order: List[Tuple[str, str, str]] = []
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.title)
        existing = groups.get(key)
        if existing is None:
            clone = copy.copy(finding)
            clone.other_jobs = []
            clone.other_lines = []
            groups[key] = clone
            order.append(key)
            continue
        existing.occurrences += 1
        if finding.job and finding.job not in existing.other_jobs:
            existing.other_jobs = list(existing.other_jobs) + [finding.job]
        existing.other_lines = list(existing.other_lines) + [finding.line]
        # Keep the highest score of the group so severity is never understated.
        if finding.score > existing.score:
            existing.factors = finding.factors
    return [groups[key] for key in order]


def filter_findings(findings: Iterable[Finding], min_severity: str = "info",
                    only_rules: Optional[Set[str]] = None,
                    skip_rules: Optional[Set[str]] = None) -> List[Finding]:
    threshold = SEVERITY_ORDER[min_severity]
    out: List[Finding] = []
    for finding in findings:
        if SEVERITY_ORDER[finding.severity] > threshold:
            continue
        if only_rules and finding.rule_id not in only_rules:
            continue
        if skip_rules and finding.rule_id in skip_rules:
            continue
        out.append(finding)
    return out
