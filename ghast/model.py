"""Parsed representation of a workflow (or composite action) file."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import yamlpos
from .yamlpos import PosDict, PosList


@dataclass
class Position:
    line: int = 1
    col: int = 1

    @classmethod
    def of(cls, container: Any, key: Any) -> "Position":
        if isinstance(container, PosDict):
            line, col = container.pos_of(key)
            return cls(line, col)
        if isinstance(container, PosList) and isinstance(key, int):
            line, col = container.pos_of(key)
            return cls(line, col)
        return cls()

    @classmethod
    def value_of(cls, container: Any, key: Any) -> "Position":
        if isinstance(container, PosDict):
            line, col = container.value_pos_of(key)
            return cls(line, col)
        return cls.of(container, key)

    @classmethod
    def node(cls, container: Any) -> "Position":
        if isinstance(container, (PosDict, PosList)):
            return cls(container.line, container.col)
        return cls()


@dataclass
class UsesRef:
    """A parsed ``uses:`` value."""

    raw: str
    owner: Optional[str] = None
    repo: Optional[str] = None
    subpath: Optional[str] = None
    ref: Optional[str] = None
    local: bool = False
    docker: bool = False

    @property
    def slug(self) -> str:
        if self.local or self.docker or not self.owner:
            return self.raw
        return "{}/{}".format(self.owner, self.repo)

    @property
    def full_path(self) -> str:
        """``owner/repo/subpath`` -- distinguishes actions/cache from actions/cache/restore."""
        if self.local or self.docker or not self.owner:
            return self.raw
        return "{}/{}{}".format(self.owner, self.repo, self.subpath or "")

    @property
    def is_sha_pinned(self) -> bool:
        return bool(self.ref) and re.fullmatch(r"[0-9a-f]{40}", self.ref or "") is not None

    @property
    def is_expression(self) -> bool:
        return "${{" in self.raw


_USES_RE = re.compile(
    r"^(?P<owner>[^/@\s]+)/(?P<repo>[^/@\s]+)(?P<subpath>(?:/[^@\s]+)?)"
    r"(?:@(?P<ref>.+))?$"
)


def parse_uses(raw: str) -> UsesRef:
    value = (raw or "").strip()
    if value.startswith("./") or value.startswith(".\\") or value == ".":
        return UsesRef(raw=value, local=True, subpath=value)
    if value.startswith("docker://"):
        return UsesRef(raw=value, docker=True)
    m = _USES_RE.match(value)
    if not m:
        return UsesRef(raw=value)
    return UsesRef(
        raw=value,
        owner=m.group("owner"),
        repo=m.group("repo"),
        subpath=m.group("subpath") or None,
        ref=m.group("ref"),
    )


@dataclass
class Step:
    index: int
    job_id: str
    raw: Any
    pos: Position
    id: Optional[str] = None
    name: Optional[str] = None
    run: Optional[str] = None
    run_pos: Position = field(default_factory=Position)
    shell: Optional[str] = None
    uses: Optional[UsesRef] = None
    uses_pos: Position = field(default_factory=Position)
    with_: Dict[str, Any] = field(default_factory=dict)
    env: Dict[str, Any] = field(default_factory=dict)
    if_: Optional[str] = None
    continue_on_error: Any = None

    @property
    def label(self) -> str:
        if self.name:
            return self.name
        if self.uses:
            return "uses: {}".format(self.uses.raw)
        if self.run:
            first = self.run.strip().splitlines()[0] if self.run.strip() else ""
            return "run: {}".format(first[:48])
        return "step #{}".format(self.index)


@dataclass
class Job:
    id: str
    raw: Any
    pos: Position
    name: Optional[str] = None
    runs_on: List[str] = field(default_factory=list)
    runs_on_pos: Position = field(default_factory=Position)
    runs_on_group: Optional[str] = None
    steps: List[Step] = field(default_factory=list)
    env: Dict[str, Any] = field(default_factory=dict)
    permissions: Any = None
    permissions_pos: Position = field(default_factory=Position)
    permissions_key_pos: Position = field(default_factory=Position)
    if_: Optional[str] = None
    if_pos: Position = field(default_factory=Position)
    needs: List[str] = field(default_factory=list)
    outputs: Dict[str, Any] = field(default_factory=dict)
    uses: Optional[UsesRef] = None          # reusable workflow call
    secrets_inherit: bool = False
    environment: Any = None
    strategy_matrix: Any = None

    @property
    def is_self_hosted(self) -> bool:
        """A runner that outlives the job, so state can be left behind.

        Explicit `self-hosted`, a runner group, or any label we cannot place.
        Deliberately *not* included: GitHub's own larger runners, and the
        managed-ephemeral providers, whose VMs are destroyed after each job.
        """
        from .knowledge import is_hosted_runner_label, is_managed_runner_label

        if self.runs_on_group:
            return True
        for label in self.runs_on:
            low = label.strip().strip("\"'").lower()
            if low == "self-hosted":
                return True
            if "${{" in label or not low:
                continue
            if is_hosted_runner_label(low) or is_managed_runner_label(low):
                continue
            return True
        return False

    @property
    def managed_runner(self) -> Optional[str]:
        from .knowledge import is_managed_runner_label

        for label in self.runs_on:
            if is_managed_runner_label(label):
                return label.strip()
        return None


@dataclass
class Workflow:
    path: str
    text: str
    raw: Any
    name: Optional[str] = None
    events: Dict[str, Any] = field(default_factory=dict)
    events_pos: Position = field(default_factory=Position)
    jobs: Dict[str, Job] = field(default_factory=dict)
    env: Dict[str, Any] = field(default_factory=dict)
    permissions: Any = None
    permissions_pos: Position = field(default_factory=Position)
    permissions_key_pos: Position = field(default_factory=Position)
    kind: str = "workflow"                  # or "action"
    parse_error: Optional[str] = None

    @property
    def event_names(self) -> List[str]:
        return list(self.events.keys())

    def line_text(self, line: int) -> str:
        lines = self.text.splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1]
        return ""


def _as_dict(value: Any) -> Dict[str, Any]:
    # Returned as-is rather than copied: PosDict carries the line numbers we
    # need later, and dict() would flatten them away.
    return value if isinstance(value, dict) else {}


def _as_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _normalise_events(value: Any) -> Dict[str, Any]:
    if isinstance(value, str):
        return {value: {}}
    if isinstance(value, list):
        return {v: {} for v in value if isinstance(v, str)}
    if isinstance(value, dict):
        return {k: (v if v is not None else {}) for k, v in value.items()}
    return {}


def _build_steps(job_id: str, steps_raw: Any) -> List[Step]:
    steps: List[Step] = []
    if not isinstance(steps_raw, list):
        return steps
    for idx, raw in enumerate(steps_raw):
        if not isinstance(raw, dict):
            continue
        step = Step(index=idx, job_id=job_id, raw=raw, pos=Position.of(steps_raw, idx))
        step.id = raw.get("id") if isinstance(raw.get("id"), str) else None
        step.name = raw.get("name") if isinstance(raw.get("name"), str) else None
        if isinstance(raw.get("run"), str):
            step.run = raw["run"]
            step.run_pos = Position.value_of(raw, "run")
        if isinstance(raw.get("shell"), str):
            step.shell = raw["shell"]
        if isinstance(raw.get("uses"), str):
            step.uses = parse_uses(raw["uses"])
            step.uses_pos = Position.value_of(raw, "uses")
        step.with_ = _as_dict(raw.get("with"))
        step.env = _as_dict(raw.get("env"))
        step.if_ = raw.get("if") if isinstance(raw.get("if"), (str, bool)) else None
        if isinstance(step.if_, bool):
            step.if_ = str(step.if_)
        step.continue_on_error = raw.get("continue-on-error")
        steps.append(step)
    return steps


def _build_job(job_id: str, raw: Any, container: Any) -> Job:
    job = Job(id=str(job_id), raw=raw, pos=Position.of(container, job_id))
    if not isinstance(raw, dict):
        return job
    job.name = raw.get("name") if isinstance(raw.get("name"), str) else None
    runs_on = raw.get("runs-on")
    job.runs_on_pos = Position.value_of(raw, "runs-on")
    if isinstance(runs_on, dict):
        job.runs_on = _as_str_list(runs_on.get("labels"))
        group = runs_on.get("group")
        job.runs_on_group = group if isinstance(group, str) else None
    else:
        job.runs_on = _as_str_list(runs_on)
    job.steps = _build_steps(job.id, raw.get("steps"))
    job.env = _as_dict(raw.get("env"))
    job.permissions = raw.get("permissions")
    job.permissions_pos = Position.value_of(raw, "permissions")
    job.permissions_key_pos = Position.of(raw, "permissions")
    if_value = raw.get("if")
    job.if_ = if_value if isinstance(if_value, str) else (str(if_value) if isinstance(if_value, bool) else None)
    job.if_pos = Position.value_of(raw, "if")
    job.needs = _as_str_list(raw.get("needs"))
    job.outputs = _as_dict(raw.get("outputs"))
    if isinstance(raw.get("uses"), str):
        job.uses = parse_uses(raw["uses"])
    secrets = raw.get("secrets")
    job.secrets_inherit = secrets == "inherit" or isinstance(secrets, dict)
    job.environment = raw.get("environment")
    strategy = raw.get("strategy")
    if isinstance(strategy, dict):
        job.strategy_matrix = strategy.get("matrix")
    return job


def parse_text(text: str, path: str) -> Workflow:
    wf = Workflow(path=path, text=text, raw=None)
    try:
        data = yamlpos.load(text)
    except Exception as exc:  # noqa: BLE001 - surfaced as a finding, not a crash
        wf.parse_error = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        return wf
    if not isinstance(data, dict):
        wf.parse_error = "top-level YAML document is not a mapping"
        return wf
    wf.raw = data
    wf.name = data.get("name") if isinstance(data.get("name"), str) else None

    runs = data.get("runs")
    if isinstance(runs, dict) and "using" in runs:
        # A composite / JS action definition rather than a workflow.
        wf.kind = "action"
        if str(runs.get("using", "")).lower() == "composite":
            synthetic = Job(id="runs", raw=runs, pos=Position.value_of(data, "runs"))
            synthetic.steps = _build_steps("runs", runs.get("steps"))
            synthetic.runs_on = ["composite"]
            wf.jobs["runs"] = synthetic
        return wf

    wf.events = _normalise_events(data.get("on"))
    wf.events_pos = Position.value_of(data, "on")
    wf.env = _as_dict(data.get("env"))
    wf.permissions = data.get("permissions")
    wf.permissions_pos = Position.value_of(data, "permissions")
    wf.permissions_key_pos = Position.of(data, "permissions")

    jobs_raw = data.get("jobs")
    if isinstance(jobs_raw, dict):
        for job_id, job_raw in jobs_raw.items():
            wf.jobs[str(job_id)] = _build_job(str(job_id), job_raw, jobs_raw)
    return wf


def parse_file(path: str) -> Workflow:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_text(handle.read(), path)
