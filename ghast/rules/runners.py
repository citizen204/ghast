"""Rules about where the job runs and what it leaves behind."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .. import knowledge
from ..findings import (
    IMPACT_HYGIENE, IMPACT_PERSISTENCE, IMPACT_RUNNER, Finding, RuleMeta,
    ScoreFactors, register, sentence as _sentence,
)
from ..model import Job, Step
from . import rule
from .base import Context, guard_description, job_guard, worst_trigger

DOCS_SELF_HOSTED = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners"
DOCS_CREDS = "https://github.com/actions/checkout#usage"

SELF_HOSTED_PUBLIC = register(RuleMeta(
    id="GHAST030",
    name="self-hosted-runner-untrusted-code",
    summary="A self-hosted runner executes code from outsiders",
    description=(
        "GitHub-hosted runners are destroyed after every job; self-hosted runners are not. "
        "A fork pull request that runs on one can write to the filesystem, poison the tool "
        "cache, leave a background process, or read credentials belonging to other jobs on "
        "the same machine -- and everything it leaves behind is waiting for the next, "
        "possibly privileged, job."
    ),
    remediation=(
        "Do not run fork pull requests on self-hosted runners. Use GitHub-hosted runners "
        "for untrusted code, require approval for outside contributors under Settings -> "
        "Actions, and if you must self-host, use ephemeral single-job runners in an "
        "isolated network segment."
    ),
    references=(DOCS_SELF_HOSTED,),
    tags=("self-hosted", "persistence"),
))

PERSIST_CREDENTIALS = register(RuleMeta(
    id="GHAST031",
    name="persisted-git-credentials",
    summary="checkout leaves a usable token in .git/config while untrusted code runs",
    description=(
        "`actions/checkout` writes an authenticated remote into `.git/config` by default "
        "and leaves it there for the rest of the job. Any code that subsequently executes "
        "in that workspace -- an install script, a test, a Makefile target -- can read the "
        "token out of the config and push with it."
    ),
    remediation=(
        "Set `persist-credentials: false` on checkout in any job that goes on to execute "
        "code from the tree, and pass a scoped token explicitly to the steps that need one."
    ),
    references=(DOCS_CREDS,),
    tags=("secrets", "hardening"),
))

CONTINUE_ON_ERROR_GATE = register(RuleMeta(
    id="GHAST032",
    name="ignored-gate-failure",
    summary="A validation step cannot fail the workflow",
    description=(
        "`continue-on-error: true` on a step whose purpose is to reject bad input means a "
        "failure is recorded and then ignored, and the steps it was meant to protect run "
        "anyway."
    ),
    remediation="Remove `continue-on-error` from validation steps, or branch on the step's outcome.",
    references=(DOCS_SELF_HOSTED,),
    tags=("hardening",),
))


@rule
def self_hosted_untrusted(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if ctx.wf.kind == "action":
        return findings
    outsider_events = sorted(e for e in ctx.events if ctx.trigger(e).outsider)
    if not outsider_events:
        return findings
    trigger = worst_trigger(set(outsider_events), ctx)
    for job in ctx.wf.jobs.values():
        if not job.is_self_hosted:
            continue
        labels = job.runs_on_group or ", ".join(job.runs_on) or "(unresolved)"
        if job.runs_on_group:
            labels = "group: " + labels
        third_party = job.runner_class == knowledge.RUNNER_THIRD_PARTY
        impact = IMPACT_PERSISTENCE
        confidence = "certain"
        notes = [
            "reachable via `{}`, which any GitHub user can fire".format(trigger.name),
            "runner labels: {}".format(labels),
        ]
        if third_party:
            impact *= 0.6
            confidence = "likely"
            notes.append(
                "`{}` is a third-party managed runner, not one of this repository's own "
                "machines. Whether it is torn down between jobs is the provider's "
                "business and is not visible here -- if it is ephemeral, the persistence "
                "argument below does not apply".format(labels)
            )
        else:
            notes.append("state left on the machine survives into later jobs")
        if trigger.secrets:
            notes.append("this trigger also grants repository secrets")
        _note_guard(ctx, job, None, notes)
        findings.append(Finding(
            rule_id=SELF_HOSTED_PUBLIC.id,
            title="{} runner is reachable by `{}`".format(
                "Third-party managed" if third_party else "Self-hosted", trigger.name),
            path=ctx.wf.path, line=job.runs_on_pos.line, job=job.id,
            message=_sentence(SELF_HOSTED_PUBLIC.summary) + " " +
                    _sentence(SELF_HOSTED_PUBLIC.description, 1),
            evidence="runs-on: {}".format(labels),
            remediation=SELF_HOSTED_PUBLIC.remediation,
            references=SELF_HOSTED_PUBLIC.references,
            tags=SELF_HOSTED_PUBLIC.tags,
            factors=ScoreFactors(
                impact=impact, actor=trigger.actor, confidence=confidence,
                guard=job_guard(job, None, ctx), notes=notes,
            ),
            fingerprint_extra="self-hosted",
        ))
    return findings


@rule
def persisted_credentials(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    for job in ctx.wf.jobs.values():
        checkout: Optional[Step] = None
        for step in job.steps:
            slug = (step.uses.slug or "").lower() if step.uses else ""
            if slug not in knowledge.CHECKOUT_ACTIONS:
                continue
            persist = (step.with_ or {}).get("persist-credentials")
            if str(persist).lower() == "false":
                continue
            checkout = step
            break
        if checkout is None:
            continue
        runner: Optional[Step] = None
        for step in job.steps:
            if step.index <= checkout.index or not step.run:
                continue
            if knowledge.detect_repo_code_execution(step.run):
                runner = step
                break
        if runner is None:
            continue
        trigger = worst_trigger(ctx.events, ctx)
        findings.append(Finding(
            rule_id=PERSIST_CREDENTIALS.id,
            title="Job `{}` runs build tooling with a persisted git token".format(job.id),
            path=ctx.wf.path, line=checkout.pos.line, job=job.id, step=checkout.label,
            message=_sentence(PERSIST_CREDENTIALS.summary) + " " +
                    _sentence(PERSIST_CREDENTIALS.description, 1),
            evidence="uses: {} (persist-credentials defaults to true)".format(
                checkout.uses.raw if checkout.uses else "actions/checkout"),
            remediation=PERSIST_CREDENTIALS.remediation,
            references=PERSIST_CREDENTIALS.references,
            tags=PERSIST_CREDENTIALS.tags,
            factors=ScoreFactors(
                impact=IMPACT_HYGIENE * 1.6,
                actor=trigger.actor if trigger.outsider else knowledge.ACTOR_WRITE,
                notes=["`{}` runs after checkout in the same workspace".format(runner.label)],
            ),
            fingerprint_extra="persist-credentials",
        ))
    return findings


_GATE_WORDS = re.compile(r"\b(verify|validate|check|lint|audit|scan|gate|guard|"
                         r"signature|checksum|policy|approve)\b", re.IGNORECASE)


@rule
def ignored_gate_failures(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    for job in ctx.wf.jobs.values():
        for step in job.steps:
            if str(step.continue_on_error).lower() != "true":
                continue
            label = " ".join(filter(None, [step.name or "", step.uses.raw if step.uses else "",
                                           (step.run or "")[:120]]))
            if not _GATE_WORDS.search(label):
                continue
            findings.append(Finding(
                rule_id=CONTINUE_ON_ERROR_GATE.id,
                title="Validation step `{}` cannot fail the job".format(step.label),
                path=ctx.wf.path, line=step.pos.line, job=job.id, step=step.label,
                message=_sentence(CONTINUE_ON_ERROR_GATE.summary) + " " + CONTINUE_ON_ERROR_GATE.description,
                evidence="continue-on-error: true",
                remediation=CONTINUE_ON_ERROR_GATE.remediation,
                references=CONTINUE_ON_ERROR_GATE.references,
                tags=CONTINUE_ON_ERROR_GATE.tags,
                factors=ScoreFactors(impact=IMPACT_HYGIENE, actor=knowledge.ACTOR_WRITE,
                                     notes=["the step's failure is recorded but ignored"]),
                fingerprint_extra="continue-on-error",
            ))
    return findings


def _note_guard(ctx, job, step, notes):
    """Append the `if:` gating explanation so the score is self-justifying."""
    description = guard_description(job, step, ctx)
    if description:
        notes.append("gated by an `if:` condition: " + description)
    return notes
