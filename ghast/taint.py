"""Cross-job taint propagation.

Attacker data rarely reaches a shell in one step.  The interesting real-world
shape is four hops::

    github.event.issue.title
      -> job-level env: TITLE
      -> `echo "slug=$TITLE" >> $GITHUB_OUTPUT`   (step output)
      -> `needs.prepare.outputs.slug`             (another job)
      -> `run: deploy ${{ needs.prepare.outputs.slug }}`

A rule that only looks at one ``run:`` block at a time sees nothing here.  This
module walks jobs in dependency order, carrying a symbol table of tainted
environment variables, step outputs, job outputs and matrix entries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import expr, knowledge, shell
from .knowledge import Source
from .model import Job, Step, Workflow

CONFIDENCE_CERTAIN = "certain"
CONFIDENCE_LIKELY = "likely"


@dataclass(frozen=True)
class Hop:
    """One link in a propagation chain."""

    description: str
    line: int


@dataclass(frozen=True)
class Flow:
    """Attacker data, plus how it got where it is."""

    source: Source
    path: str
    origin_line: int
    hops: Tuple[Hop, ...] = ()
    confidence: str = CONFIDENCE_CERTAIN

    def extend(self, description: str, line: int,
               confidence: Optional[str] = None) -> "Flow":
        return replace(
            self,
            hops=self.hops + (Hop(description, line),),
            confidence=confidence or self.confidence,
        )

    @property
    def chain(self) -> List[str]:
        out = ["{} (line {})".format(self.path, self.origin_line)]
        out.extend("{} (line {})".format(h.description, h.line) for h in self.hops)
        return out

    @property
    def depth(self) -> int:
        return len(self.hops)


# Sink kinds --------------------------------------------------------------
SINK_RUN_INTERPOLATION = "run-interpolation"
SINK_RUN_ENV_EXEC = "run-env-exec"
SINK_RUN_ENV_ARG = "run-env-arg"
SINK_ENV_FILE = "env-file"
SINK_SCRIPT_INPUT = "script-input"
SINK_USES_REF = "uses-ref"
SINK_ACTION_INPUT = "action-input"


@dataclass
class SinkHit:
    kind: str
    job: Job
    step: Optional[Step]
    flow: Flow
    line: int
    detail: str
    target: str = ""
    evidence: str = ""


@dataclass
class JobFacts:
    """What the engine learned about a job, for other rules to reuse."""

    job: Job
    tainted_env: Dict[str, List[Flow]] = field(default_factory=dict)
    step_outputs: Dict[str, List[Flow]] = field(default_factory=dict)
    reachable_events: Set[str] = field(default_factory=set)


def _symbol_for(path: str) -> Optional[str]:
    parts = path.split(".")
    if parts[0] == "env" and len(parts) >= 2:
        return "env:" + parts[1]
    if parts[0] == "steps" and len(parts) >= 4 and parts[2] in ("outputs", "output"):
        return "steps:{}.{}".format(parts[1], parts[3])
    if parts[0] == "needs" and len(parts) >= 4 and parts[2] == "outputs":
        return "needs:{}.{}".format(parts[1], parts[3])
    if parts[0] == "matrix" and len(parts) >= 2:
        return "matrix:" + parts[1]
    if parts[0] == "jobs" and len(parts) >= 4 and parts[2] == "outputs":
        return "needs:{}.{}".format(parts[1], parts[3])
    return None


def _topological(jobs: Dict[str, Job]) -> List[Job]:
    ordered: List[Job] = []
    seen: Set[str] = set()
    visiting: Set[str] = set()

    def visit(job_id: str) -> None:
        if job_id in seen or job_id in visiting or job_id not in jobs:
            return
        visiting.add(job_id)
        for dep in jobs[job_id].needs:
            visit(dep)
        visiting.discard(job_id)
        seen.add(job_id)
        ordered.append(jobs[job_id])

    for job_id in jobs:
        visit(job_id)
    return ordered


class TaintEngine:
    def __init__(self, workflow: Workflow) -> None:
        self.wf = workflow
        self.events: Set[str] = set(workflow.event_names)
        self.is_action = workflow.kind == "action"
        self.sinks: List[SinkHit] = []
        self.facts: Dict[str, JobFacts] = {}
        self._job_outputs: Dict[str, List[Flow]] = {}

    # -- reachability ------------------------------------------------------
    def _path_reachable(self, path: str) -> bool:
        if self.is_action:
            return True          # a composite action can be called from anywhere
        allowed = knowledge.events_for_path(path)
        if allowed is None:
            return True
        return bool(allowed & self.events)

    # -- expression evaluation --------------------------------------------
    def flows_in(self, value: object, state: Dict[str, List[Flow]],
                 line: int) -> List[Flow]:
        """Every tainted flow reaching the *value* of an expression."""
        out: List[Flow] = []
        for ref in expr.refs(value):
            if ref.in_predicate:
                continue
            source = knowledge.match_source(ref.path)
            if source is not None and self._path_reachable(ref.path):
                out.append(Flow(source=source, path=ref.path, origin_line=line))
                continue
            symbol = _symbol_for(ref.path)
            if symbol and symbol in state:
                for flow in state[symbol]:
                    out.append(flow.extend("read as {}".format(ref.path), line))
        return _dedupe(out)

    # -- main pass ---------------------------------------------------------
    def run(self) -> "TaintEngine":
        base_env: Dict[str, List[Flow]] = {}
        wf_env_line = getattr(self.wf.raw, "line", 1) if self.wf.raw else 1
        for name, value in (self.wf.env or {}).items():
            line = value_line(self.wf.env, name, wf_env_line)
            found = self.flows_in(value, {}, line)
            if found:
                base_env["env:" + str(name)] = [
                    f.extend("workflow env {}".format(name), line) for f in found
                ]

        for job in _topological(self.wf.jobs):
            self._analyse_job(job, base_env)
        return self

    def _analyse_job(self, job: Job, base_env: Dict[str, List[Flow]]) -> None:
        state: Dict[str, List[Flow]] = {k: list(v) for k, v in base_env.items()}
        # Upstream job outputs become `needs.<job>.outputs.<name>`.
        for dep in job.needs:
            for key, flows in self._job_outputs.items():
                if key.startswith(dep + "."):
                    state["needs:" + key] = list(flows)

        for name, value in (job.env or {}).items():
            line = value_line(job.env, name, job.pos.line)
            found = self.flows_in(value, state, line)
            if found:
                state["env:" + str(name)] = [
                    f.extend("job env {}".format(name), line) for f in found
                ]
            else:
                state.pop("env:" + str(name), None)

        self._seed_matrix(job, state)

        facts = JobFacts(job=job, reachable_events=set(self.events))
        for step in job.steps:
            self._analyse_step(job, step, state)
        facts.tainted_env = {k[4:]: v for k, v in state.items() if k.startswith("env:")}
        facts.step_outputs = {k[6:]: v for k, v in state.items() if k.startswith("steps:")}
        self.facts[job.id] = facts

        for name, value in (job.outputs or {}).items():
            line = value_line(job.outputs, name, job.pos.line)
            found = self.flows_in(value, state, line)
            if found:
                self._job_outputs["{}.{}".format(job.id, name)] = [
                    f.extend("job output {}.{}".format(job.id, name), line)
                    for f in found
                ]

    def _seed_matrix(self, job: Job, state: Dict[str, List[Flow]]) -> None:
        matrix = job.strategy_matrix
        if matrix is None:
            return
        for path, value in expr.iter_strings(matrix):
            found = self.flows_in(value, state, job.pos.line)
            if not found:
                continue
            key = path.split(".")[0].split("[")[0] if path else "*"
            state["matrix:" + key] = [
                f.extend("matrix entry {}".format(key), job.pos.line) for f in found
            ]

    # -- step analysis -----------------------------------------------------
    def _analyse_step(self, job: Job, step: Step, state: Dict[str, List[Flow]]) -> None:
        # Step-level env shadows job env, but only inside this step.
        step_state = dict(state)
        for name, value in (step.env or {}).items():
            line = value_line(step.env, name, step.pos.line)
            found = self.flows_in(value, state, line)
            if found:
                step_state["env:" + str(name)] = [
                    f.extend("step env {}".format(name), line) for f in found
                ]
            else:
                step_state.pop("env:" + str(name), None)

        if step.run is not None:
            self._analyse_run(job, step, step_state, state)
        if step.uses is not None:
            self._analyse_uses(job, step, step_state, state)

    def _script_base_line(self, step: Step) -> int:
        line = step.run_pos.line
        text = self.wf.line_text(line)
        if re.search(r"run\s*:\s*[|>][-+0-9]*\s*(#.*)?$", text):
            return line + 1
        return line

    def _analyse_run(self, job: Job, step: Step, step_state: Dict[str, List[Flow]],
                     job_state: Dict[str, List[Flow]]) -> None:
        script = step.run or ""
        base_line = self._script_base_line(step)
        quoting = shell.quote_map(script)

        # (1) Direct template substitution: the value is pasted in before the
        #     shell ever sees the script, so quoting in the YAML cannot help.
        for interp in expr.interpolations(script):
            if interp.start < len(quoting) and quoting[interp.start] == "comment":
                continue
            for flow in self._interp_flows(interp, step_state, base_line, script):
                self.sinks.append(
                    SinkHit(
                        kind=SINK_RUN_INTERPOLATION,
                        job=job, step=step, flow=flow,
                        line=base_line + script.count("\n", 0, interp.start),
                        detail="The expression is expanded into the script text before any "
                               "shell parses it, so quoting cannot contain it.",
                        target=interp.raw.strip(),
                        evidence=_evidence(script, interp.start),
                    )
                )

        # (2) Reads of a tainted environment variable.
        for symbol, flows in step_state.items():
            if not symbol.startswith("env:"):
                continue
            name = symbol[4:]
            for use in shell.find_var_uses(script, name):
                line = base_line + script.count("\n", 0, use.offset)
                if use.is_execution:
                    for flow in flows:
                        self.sinks.append(
                            SinkHit(
                                kind=SINK_RUN_ENV_EXEC,
                                job=job, step=step,
                                flow=flow.extend("read ${} in command position".format(name), line),
                                line=line,
                                detail="The variable's contents are re-parsed as a command here.",
                                target="${}".format(name),
                                evidence=use.line_text.strip(),
                            )
                        )
                elif use.is_argument_injection:
                    for flow in flows:
                        self.sinks.append(
                            SinkHit(
                                kind=SINK_RUN_ENV_ARG,
                                job=job, step=step,
                                flow=flow.extend("read unquoted ${}".format(name), line),
                                line=line,
                                detail="The unquoted expansion lets the attacker append "
                                       "arguments or flags to this command.",
                                target="${}".format(name),
                                evidence=use.line_text.strip(),
                            )
                        )

        # (3) Writes into the runner's environment files.
        self._analyse_env_file_writes(job, step, step_state, job_state, script, base_line)

    def _interp_flows(self, interp: expr.Interpolation, state: Dict[str, List[Flow]],
                      base_line: int, script: str) -> List[Flow]:
        line = base_line + script.count("\n", 0, interp.start)
        return self.flows_in(interp.raw, state, line)

    def _analyse_env_file_writes(self, job: Job, step: Step,
                                 step_state: Dict[str, List[Flow]],
                                 job_state: Dict[str, List[Flow]],
                                 script: str, base_line: int) -> None:
        for write in shell.find_env_file_writes(script):
            line_flows = self.flows_in(write.line_text, step_state,
                                       base_line + write.line - 1)
            for sym, flows in step_state.items():
                if not sym.startswith("env:"):
                    continue
                name = sym[4:]
                if any(u.line == write.line for u in shell.find_var_uses(script, name)):
                    line_flows.extend(
                        f.extend("written through ${}".format(name),
                                 base_line + write.line - 1) for f in flows
                    )
            line_flows = _dedupe(line_flows)
            if not line_flows:
                continue
            abs_line = base_line + write.line - 1

            if write.target in ("GITHUB_ENV", "GITHUB_PATH"):
                for flow in line_flows:
                    self.sinks.append(
                        SinkHit(
                            kind=SINK_ENV_FILE,
                            job=job, step=step,
                            flow=flow.extend("written to ${}".format(write.target), abs_line),
                            line=abs_line,
                            detail="${} is parsed line by line, so a newline in the "
                                   "value sets arbitrary variables for every later step."
                                   .format(write.target),
                            target=write.target,
                            evidence=write.line_text.strip(),
                        )
                    )
            # Whatever was written is tainted from here on.
            for name in write.names or ["*"]:
                if write.target == "GITHUB_ENV":
                    job_state["env:" + name] = [
                        f.extend("set as env {} by step".format(name), abs_line)
                        for f in line_flows
                    ]
                elif write.target == "GITHUB_OUTPUT" and step.id:
                    job_state["steps:{}.{}".format(step.id, name)] = [
                        f.extend("set as output {}.{}".format(step.id, name), abs_line)
                        for f in line_flows
                    ]

    def _analyse_uses(self, job: Job, step: Step, step_state: Dict[str, List[Flow]],
                      job_state: Dict[str, List[Flow]]) -> None:
        uses = step.uses
        assert uses is not None

        # A tainted `uses:` reference means the attacker picks the action.
        if uses.is_expression:
            for flow in self.flows_in(uses.raw, step_state, step.uses_pos.line):
                self.sinks.append(
                    SinkHit(
                        kind=SINK_USES_REF,
                        job=job, step=step, flow=flow, line=step.uses_pos.line,
                        detail="The attacker therefore chooses which code the runner fetches.",
                        target=uses.raw,
                        evidence=uses.raw,
                    )
                )

        slug = (uses.slug or "").lower()
        code_inputs = knowledge.CODE_EXECUTING_INPUTS.get(slug, ())
        with_ = step.with_ or {}
        for key, value in with_.items():
            line = value_line(with_, key, step.pos.line)
            found = self.flows_in(value, step_state, line)
            if not found:
                continue
            if str(key) in code_inputs:
                for flow in found:
                    self.sinks.append(
                        SinkHit(
                            kind=SINK_SCRIPT_INPUT,
                            job=job, step=step, flow=flow, line=line,
                            detail="{} evaluates the `{}` input as code.".format(uses.slug, key),
                            target="{}.{}".format(uses.slug, key),
                            evidence=str(value)[:160],
                        )
                    )
            else:
                for flow in found:
                    self.sinks.append(
                        SinkHit(
                            kind=SINK_ACTION_INPUT,
                            job=job, step=step, flow=flow, line=line,
                            detail="Whether this is exploitable depends on what the action does "
                                   "with the input.",
                            target="{}.{}".format(uses.slug, key),
                            evidence=str(value)[:160],
                        )
                    )
            # The action's outputs may echo its inputs back.
            if step.id:
                job_state["steps:{}.*".format(step.id)] = [
                    f.extend("may be echoed by {} outputs".format(uses.slug), line,
                             confidence=CONFIDENCE_LIKELY)
                    for f in found
                ]


def _evidence(script: str, offset: int) -> str:
    """The source line containing ``offset``, trimmed for display."""
    start = script.rfind("\n", 0, offset) + 1
    end = script.find("\n", offset)
    if end == -1:
        end = len(script)
    return script[start:end].strip()[:200]


def value_line(container: object, key: object, fallback: int = 1) -> int:
    """Line of the *value* for ``key``, falling back when positions are absent."""
    from .yamlpos import PosDict
    if isinstance(container, PosDict):
        return container.value_pos_of(key)[0]
    return fallback


def _dedupe(flows: Sequence[Flow]) -> List[Flow]:
    seen: Set[Tuple[str, int, Tuple[str, ...]]] = set()
    out: List[Flow] = []
    for flow in flows:
        key = (flow.path, flow.origin_line, tuple(h.description for h in flow.hops))
        if key in seen:
            continue
        seen.add(key)
        out.append(flow)
    return out


def analyse(workflow: Workflow) -> TaintEngine:
    return TaintEngine(workflow).run()
