"""Shared context and the privilege reasoning every rule depends on."""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .. import guards, knowledge
from ..findings import (
    IMPACT_ARGUMENT, IMPACT_PERSISTENCE, IMPACT_RUNNER, IMPACT_SECRETS,
    IMPACT_SECRETS_AND_WRITE, IMPACT_WRITE_TOKEN, ScoreFactors,
)
from ..knowledge import Trigger
from ..model import Job, Step, Workflow
from ..taint import Flow, TaintEngine


@dataclass
class Context:
    workflow: Workflow
    engine: TaintEngine
    errors: List[str] = field(default_factory=list)
    #: Sibling workflows in the same repository: display name -> its events.
    #: Empty when only one file was scanned, in which case an unresolvable
    #: `workflow_run` keeps its worst-case reading.
    index: Dict[str, Set[str]] = field(default_factory=dict)

    @property
    def wf(self) -> Workflow:
        return self.workflow

    @property
    def events(self) -> Set[str]:
        return set(self.workflow.event_names)

    def trigger(self, name: str) -> Trigger:
        """The privilege this event grants *in this workflow*.

        Identical to the static table except for `workflow_run`, whose
        reachability is a property of the workflow that triggers it.
        """
        base = knowledge.trigger(name)
        if name != "workflow_run":
            return base
        return self._resolve_workflow_run(base)

    def _resolve_workflow_run(self, base: Trigger) -> Trigger:
        spec = self.workflow.events.get("workflow_run")
        names = spec.get("workflows") if isinstance(spec, dict) else None
        if not isinstance(names, list) or not names or not self.index:
            return base                      # unknown upstream: assume the worst
        resolved_all = True
        for raw in names:
            if not isinstance(raw, str):
                return base
            events = self.index.get(raw.strip())
            if events is None:
                resolved_all = False         # upstream not in this scan
                continue
            if any(knowledge.trigger(e).outsider for e in events):
                return base                  # one outsider-reachable parent is enough
        if not resolved_all:
            return base
        return replace(
            base,
            outsider=False,
            actor=knowledge.ACTOR_WRITE,
            note="fires only after {}, which {} can start".format(
                " / ".join("`{}`".format(n) for n in names),
                "only someone with write access"),
        )


# --------------------------------------------------------------------------
# GITHUB_TOKEN permissions
# --------------------------------------------------------------------------

WRITE_SCOPES = {"contents", "packages", "deployments", "actions", "id-token",
                "pull-requests", "issues", "statuses", "checks", "pages",
                "security-events", "repository-projects", "discussions",
                "attestations"}

#: Write access here lets an attacker change what runs next time, ship code to
#: users, or mint credentials.  Write access to `issues` or `checks` lets them
#: post a comment.  Only the former is worth a finding on its own.
#:
#: `security-events` is deliberately absent.  It is required by the standard,
#: recommended SARIF-upload pattern, it cannot execute code or obtain
#: credentials, and reporting it would flag the very thing this project tells
#: people to do.  Suppressing code-scanning alerts with it is a real but
#: second-order concern, and not what this rule is for.
HIGH_BLAST_RADIUS_SCOPES = {"contents", "packages", "deployments", "actions",
                            "id-token", "attestations"}


def dangerous_write_scopes(permissions: Any) -> List[str]:
    if isinstance(permissions, str) and permissions.strip() == "write-all":
        return sorted(HIGH_BLAST_RADIUS_SCOPES)
    return sorted(set(write_scopes(permissions)) & HIGH_BLAST_RADIUS_SCOPES)


def effective_permissions(wf: Workflow, job: Optional[Job]) -> Tuple[Any, str]:
    """``(value, origin)`` for the permissions that apply to ``job``."""
    if job is not None and job.permissions is not None:
        return job.permissions, "job"
    if wf.permissions is not None:
        return wf.permissions, "workflow"
    return None, "default"


def token_is_write(permissions: Any) -> Optional[bool]:
    """``None`` means "repository default", which we cannot see from the file."""
    if permissions is None:
        return None
    if isinstance(permissions, str):
        return permissions.strip() == "write-all"
    if isinstance(permissions, dict):
        if not permissions:
            return False
        return any(str(v).strip() == "write" for v in permissions.values())
    return None


def write_scopes(permissions: Any) -> List[str]:
    if isinstance(permissions, str) and permissions.strip() == "write-all":
        return sorted(WRITE_SCOPES)
    if isinstance(permissions, dict):
        return sorted(k for k, v in permissions.items() if str(v).strip() == "write")
    return []


# --------------------------------------------------------------------------
# Trigger selection
# --------------------------------------------------------------------------

def _trigger_reach(t: Trigger) -> Tuple[int, int, int]:
    """Sort key: prefer outsider-reachable, then secret-bearing, then write."""
    return (1 if t.outsider else 0, 1 if t.secrets else 0, 1 if t.token_write else 0)


def worst_trigger(events: Set[str], ctx: Optional["Context"] = None) -> Trigger:
    if not events:
        return knowledge.UNKNOWN_TRIGGER
    resolve = ctx.trigger if ctx is not None else knowledge.trigger
    return max((resolve(e) for e in events), key=_trigger_reach)


def triggers_for_flow(ctx: Context, flow: Flow) -> Trigger:
    """The most attacker-favourable event that can actually supply ``flow``."""
    allowed = knowledge.events_for_path(flow.path)
    candidates = ctx.events if allowed is None else (ctx.events & set(allowed))
    if not candidates:
        candidates = ctx.events
    return worst_trigger(candidates, ctx)


def required_actor(source_actor: str, trigger: Trigger) -> str:
    """The attacker needs to satisfy *both* constraints, so take the stricter."""
    if knowledge.actor_rank(source_actor) <= knowledge.actor_rank(trigger.actor):
        return source_actor
    return trigger.actor


#: `if: needs.check-permissions.outputs.is_authorized == 'true'` -- a very
#: common shape where the authorisation decision is delegated to an earlier job.
_DELEGATED_RE = re.compile(
    r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]*"
    r"(?:auth|approv|permit|allow|member|collaborat|trusted|safe|internal)"
    r"[A-Za-z0-9_-]*)\s*[=!]=",
    re.IGNORECASE,
)

#: Evidence that a gate job really does check who the actor is.
_AUTH_MARKERS = (
    "author_association", "getcollaboratorpermissionlevel", "collaborator",
    "permission", "'owner'", '"owner"', "'member'", '"member"', "team",
    "repos.checkcollaborator", "orgs.checkmembership",
)


def _delegated_guard(ctx: "Context", job: Optional[Job]) -> Optional[guards.Guard]:
    """Recognise `needs.<gate>.outputs.<authorised>` and check the gate is real."""
    if job is None or not job.if_:
        return None
    match = _DELEGATED_RE.search(job.if_)
    if not match:
        return None
    gate_id, output = match.group(1), match.group(2)
    gate = ctx.wf.jobs.get(gate_id)
    if gate is None:
        return guards.Guard(guards.WEAK,
                            "gated on `needs.{}.outputs.{}`, but that job is not defined "
                            "in this workflow".format(gate_id, output))
    from .. import expr
    haystack = " ".join(
        str(value).lower() for _, value in expr.iter_strings(gate.raw)
    )
    if any(marker in haystack for marker in _AUTH_MARKERS):
        return guards.Guard(
            guards.STRONG,
            "authorisation delegated to job `{}`, which checks the actor's "
            "association with the repository".format(gate_id),
        )
    return guards.Guard(
        guards.WEAK,
        "gated on `needs.{}.outputs.{}`, but job `{}` was not seen checking who the "
        "actor is".format(gate_id, output, gate_id),
    )


def _best_guard(ctx: Optional["Context"], job: Optional[Job],
                step: Optional[Step]) -> Optional[guards.Guard]:
    candidates: List[Optional[guards.Guard]] = []
    conditions: List[Optional[str]] = []
    if job is not None:
        conditions.append(job.if_)
    if step is not None:
        conditions.append(step.if_)
    candidates.append(guards.strongest(conditions))
    if ctx is not None:
        candidates.append(_delegated_guard(ctx, job))
    found = [g for g in candidates if g is not None]
    if not found:
        return None
    for guard in found:
        if guard.strength == guards.STRONG:
            return guard
    return found[0]


def job_guard(job: Optional[Job], step: Optional[Step],
              ctx: Optional["Context"] = None) -> Optional[str]:
    guard = _best_guard(ctx, job, step)
    return guard.strength if guard else None


def guard_description(job: Optional[Job], step: Optional[Step],
                      ctx: Optional["Context"] = None) -> Optional[str]:
    guard = _best_guard(ctx, job, step)
    return guard.description if guard else None


# --------------------------------------------------------------------------
# Impact
# --------------------------------------------------------------------------

def execution_impact(ctx: Context, job: Job, trigger: Trigger) -> Tuple[float, List[str]]:
    """What arbitrary code execution in ``job`` is worth to an attacker."""
    notes: List[str] = []
    permissions, origin = effective_permissions(ctx.wf, job)
    writable = token_is_write(permissions)

    if job.is_self_hosted:
        notes.append("runs on a self-hosted runner, so compromise can outlive the job")
        return IMPACT_PERSISTENCE, notes

    if not trigger.secrets and not trigger.token_write:
        notes.append(
            "{} grants a read-only token and no secrets, so the immediate prize is the "
            "runner itself".format(trigger.name)
        )
        return IMPACT_RUNNER, notes

    has_env_secrets = bool(job.environment)
    if writable is False:
        notes.append("permissions ({}) keep GITHUB_TOKEN read-only".format(origin))
        return IMPACT_SECRETS, notes
    if writable is None:
        notes.append(
            "no permissions: block, so GITHUB_TOKEN keeps the repository default "
            "(write on repositories created before the read-only default)"
        )
    else:
        scopes = write_scopes(permissions)
        notes.append("GITHUB_TOKEN has write access to: {}".format(
            ", ".join(scopes) if scopes else "all scopes"))
    if has_env_secrets:
        notes.append("job targets environment '{}', whose secrets are in scope".format(
            job.environment if isinstance(job.environment, str) else "(configured)"))
    return IMPACT_SECRETS_AND_WRITE, notes


def factors_for_flow(ctx: Context, job: Job, step: Optional[Step], flow: Flow,
                     impact: Optional[float] = None) -> ScoreFactors:
    trigger = triggers_for_flow(ctx, flow)
    computed_impact, notes = execution_impact(ctx, job, trigger)
    actor = required_actor(flow.source.actor, trigger)
    guard = job_guard(job, step, ctx)
    description = guard_description(job, step, ctx)
    if description:
        notes.append("gated by an `if:` condition: {}".format(description))
    notes.insert(0, "reachable via `{}` ({})".format(trigger.name, trigger.note))
    return ScoreFactors(
        impact=impact if impact is not None else computed_impact,
        actor=actor,
        guard=guard,
        confidence=flow.confidence,
        notes=notes,
    )


def step_label(step: Optional[Step]) -> Optional[str]:
    return step.label if step is not None else None


def job_line(job: Job) -> int:
    return job.pos.line
