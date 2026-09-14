"""Rules about *privilege*: workflows that hold secrets while touching code or
data an outsider controls."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .. import knowledge
from ..findings import (
    IMPACT_HYGIENE, IMPACT_SECRETS_AND_WRITE, Finding, RuleMeta, ScoreFactors,
    register, sentence as _sentence,
)
from ..model import Job, Step, Workflow
from . import rule
from .base import (
    Context, dangerous_write_scopes, effective_permissions, guard_description,
    job_guard, token_is_write, worst_trigger, write_scopes,
)

DOCS_PWN = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
DOCS_PERMS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"

PWN_REQUEST = register(RuleMeta(
    id="GHAST010",
    name="pwn-request",
    summary="A privileged workflow checks out code from an untrusted pull request",
    description=(
        "`pull_request_target` and `workflow_run` exist so that a workflow can act on a "
        "fork's pull request *with* the repository's secrets. They deliberately run the "
        "workflow definition from the base branch, and they deliberately do not check out "
        "the contributor's code. Overriding the checkout `ref` to point at the pull "
        "request head puts attacker-authored files on a runner that holds those secrets. "
        "Anything that then reads those files -- a build script, a lockfile-driven install, "
        "a config file, a git hook -- executes attacker code with full access."
    ),
    remediation=(
        "Split the work in two. Build and test untrusted code in a `pull_request` workflow "
        "that has no secrets, upload what you need as an artifact, and do the privileged "
        "part in a separate `workflow_run` workflow that never checks out the head. If you "
        "must check out the head in a privileged job, do nothing with it but read inert "
        "data, and gate the job on an author-association check."
    ),
    references=(DOCS_PWN,),
    tags=("pwn-request", "rce", "secrets"),
))

PWN_REQUEST_EXEC = register(RuleMeta(
    id="GHAST011",
    name="untrusted-code-execution",
    summary="A privileged workflow runs build tooling over untrusted checked-out code",
    description=(
        "After an untrusted checkout, commands like `npm ci`, `pip install`, `make` and "
        "`./gradlew` execute code that the checked-out tree controls -- install scripts, "
        "Makefile targets, build plugins. This is the step that converts a risky checkout "
        "into reliable code execution with the job's secrets."
    ),
    remediation=(
        "Do not run build tooling in a job that holds secrets and has checked out "
        "untrusted code. Move the build to an unprivileged `pull_request` job."
    ),
    references=(DOCS_PWN,),
    tags=("pwn-request", "rce", "secrets"),
))

EXCESSIVE_PERMISSIONS = register(RuleMeta(
    id="GHAST012",
    name="excessive-token-permissions",
    summary="GITHUB_TOKEN is broader than the job needs",
    description=(
        "Without a `permissions:` block the token inherits the repository default, which "
        "on older repositories is write access to every scope. `write-all` does the same "
        "explicitly. That turns any code execution in the job -- including from a "
        "compromised dependency or action -- into the ability to push commits, publish "
        "releases and alter workflows."
    ),
    remediation=(
        "Declare the minimum at the top of the workflow and widen per job:\n\n"
        "    permissions:\n"
        "      contents: read\n"
    ),
    references=(DOCS_PERMS,),
    tags=("hardening", "least-privilege"),
))

SECRETS_WITH_UNTRUSTED_CODE = register(RuleMeta(
    id="GHAST013",
    name="secrets-alongside-untrusted-code",
    summary="A job holds secrets while executing code from a pull request",
    description=(
        "Secrets given to a job are readable by every process in it. If the same job also "
        "builds or tests contributor-authored code, the contributor can read them -- no "
        "vulnerability in the workflow logic required."
    ),
    remediation=(
        "Keep secrets out of jobs that execute untrusted code. Where a fork PR genuinely "
        "needs a credential, use a short-lived OIDC token scoped to exactly one action, or "
        "move the privileged step into a separate job that does not check out the head."
    ),
    references=(DOCS_PWN,),
    tags=("secrets", "pwn-request"),
))

BOT_ACTOR_TRUST = register(RuleMeta(
    id="GHAST014",
    name="bot-identity-trust",
    summary="A privileged job is gated only on the triggering actor being a bot",
    description=(
        "`github.actor == 'dependabot[bot]'` on a `pull_request_target` workflow grants "
        "the bot's pull requests access to secrets. Dependabot pull request branches carry "
        "attacker-influenced content (dependency names, versions, changelog text pulled "
        "into the PR body), and the actor check says nothing about the contents of the "
        "diff being merged."
    ),
    remediation=(
        "Use the dedicated `dependabot` secrets store and `pull_request` rather than "
        "`pull_request_target`, and never interpolate the PR body or branch name."
    ),
    references=(DOCS_PWN,),
    tags=("pwn-request", "secrets"),
))

SECRET_EXPOSURE = register(RuleMeta(
    id="GHAST015",
    name="bulk-secret-exposure",
    summary="The whole secrets context is serialised into a step",
    description=(
        "`toJSON(secrets)` hands every repository secret to one step. Log masking covers "
        "exact matches only, so anything that transforms the blob -- base64, gzip, a JSON "
        "re-encode, splitting it across lines -- prints it in the clear."
    ),
    remediation="Reference the individual secrets the step actually needs.",
    references=(DOCS_PERMS,),
    tags=("secrets",),
))


_PR_HEAD_RE = re.compile("|".join(re.escape(m) for m in knowledge.PR_HEAD_REF_MARKERS))


def _checkout_of_untrusted_head(step: Step) -> Optional[str]:
    """Returns the offending ref expression, if this step fetches PR head code."""
    if step.uses is not None and (step.uses.slug or "").lower() in knowledge.CHECKOUT_ACTIONS:
        for key in ("ref", "repository"):
            value = (step.with_ or {}).get(key)
            if isinstance(value, str) and _PR_HEAD_RE.search(value):
                return "{}: {}".format(key, value)
    if step.run:
        for line in step.run.splitlines():
            low = line.strip()
            if not low:
                continue
            if "gh pr checkout" in low:
                return low
            if ("git fetch" in low or "git checkout" in low) and _PR_HEAD_RE.search(low):
                return low
    return None


def _runs_untrusted_tooling(step: Step) -> Optional[str]:
    if step.run:
        found = knowledge.detect_repo_code_execution(step.run)
        if found:
            return found
    if step.uses is not None:
        slug = (step.uses.slug or "").lower()
        # A setup action with caching enabled reads the tree's lockfiles and
        # restores a cache keyed off them before any explicit build step runs.
        for marker in ("setup-node", "setup-python", "setup-java", "gradle", "bazel"):
            if marker in slug and (step.with_ or {}).get("cache"):
                return slug
    return None


def _is_privileged(ctx: Context) -> bool:
    trigger = worst_trigger(ctx.events, ctx)
    return trigger.outsider and trigger.secrets


@rule
def pwn_requests(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if ctx.wf.kind == "action":
        return findings
    privileged_events = sorted(
        e for e in ctx.events
        if ctx.trigger(e).outsider and ctx.trigger(e).secrets
    )
    if not privileged_events:
        return findings
    trigger = worst_trigger(set(privileged_events), ctx)

    for job in ctx.wf.jobs.values():
        guard = job_guard(job, None, ctx)
        description = guard_description(job, None, ctx)
        checkout_index: Optional[int] = None
        for step in job.steps:
            offending = _checkout_of_untrusted_head(step)
            if offending is None:
                continue
            checkout_index = step.index
            notes = [
                "triggered by `{}`, which runs with repository secrets".format(trigger.name),
                "checkout targets the pull request head rather than the base branch",
            ]
            if description:
                notes.append("gated by an `if:` condition: {}".format(description))
            findings.append(Finding(
                rule_id=PWN_REQUEST.id,
                title="`{}` checks out untrusted pull request code".format(trigger.name),
                path=ctx.wf.path, line=step.pos.line, job=job.id, step=step.label,
                message=_sentence(PWN_REQUEST.summary) + " " + (
                    "The workflow definition comes from the base branch, but the files on "
                    "disk come from the contributor."),
                evidence=offending,
                remediation=PWN_REQUEST.remediation,
                references=PWN_REQUEST.references,
                tags=PWN_REQUEST.tags,
                factors=ScoreFactors(
                    impact=IMPACT_SECRETS_AND_WRITE, actor=trigger.actor,
                    guard=guard, notes=notes,
                ),
                fingerprint_extra="checkout",
            ))
            break

        if checkout_index is None:
            continue
        for step in job.steps:
            if step.index <= checkout_index:
                continue
            tooling = _runs_untrusted_tooling(step)
            if tooling is None:
                continue
            notes = [
                "`{}` runs after the untrusted checkout in the same job".format(tooling),
                "build tooling executes code that the checked-out tree controls",
            ]
            if description:
                notes.append("gated by an `if:` condition: {}".format(description))
            findings.append(Finding(
                rule_id=PWN_REQUEST_EXEC.id,
                title="Build tooling runs over untrusted code in a privileged job",
                path=ctx.wf.path, line=step.pos.line, job=job.id, step=step.label,
                message=_sentence(PWN_REQUEST_EXEC.summary) + " " + _sentence(PWN_REQUEST_EXEC.description, 1),
                evidence=(step.run or "").strip().splitlines()[0][:160] if step.run else (step.uses.raw if step.uses else ""),
                remediation=PWN_REQUEST_EXEC.remediation,
                references=PWN_REQUEST_EXEC.references,
                tags=PWN_REQUEST_EXEC.tags,
                factors=ScoreFactors(
                    impact=IMPACT_SECRETS_AND_WRITE, actor=trigger.actor,
                    guard=guard, notes=notes,
                ),
                fingerprint_extra="tooling:" + tooling,
            ))
            break
    return findings


@rule
def permissions_hygiene(ctx: Context) -> Iterable[Finding]:
    """One finding per *permissions declaration*, not per job.

    A workflow-level `permissions: write-all` covering eight jobs is one
    mistake in one place; reporting it eight times just trains people to
    ignore the rule.
    """
    findings: List[Finding] = []
    if ctx.wf.kind == "action" or not ctx.wf.jobs:
        return findings
    trigger = worst_trigger(ctx.events, ctx)

    groups: "dict" = {}
    for job in ctx.wf.jobs.values():
        permissions, origin = effective_permissions(ctx.wf, job)
        if token_is_write(permissions) is False:
            continue
        # A narrow, purposeful grant (`issues: write` on a labelling workflow)
        # is the thing we are asking people to do; only flag the broad ones.
        if permissions is not None and not dangerous_write_scopes(permissions):
            continue
        if origin == "job":
            key = ("job", job.id)
            line = job.permissions_key_pos.line
        elif origin == "workflow":
            key = ("workflow", None)
            line = ctx.wf.permissions_key_pos.line
        else:
            key = ("default", None)
            line = ctx.wf.events_pos.line
        groups.setdefault(key, [line, permissions, []])[2].append(job.id)

    for (origin, _), (line, permissions, job_ids) in groups.items():
        scopes = dangerous_write_scopes(permissions)
        if origin == "default":
            message = (
                "No `permissions:` block applies, so GITHUB_TOKEN inherits the repository "
                "default. On repositories created before GitHub changed that default, and on "
                "any repository where it was switched back, that is write access to every "
                "scope."
            )
            evidence = "(no permissions: block)"
        else:
            message = (
                "The token has write access to {}. Any code execution in this workflow -- "
                "including from a dependency or a third-party action -- inherits that."
            ).format(", ".join(scopes) if scopes else "every scope")
            evidence = "permissions: {}".format(permissions)
        notes = [
            "declared at the {} level, covering job(s): {}".format(
                origin if origin != "default" else "repository",
                ", ".join(sorted(job_ids))),
            "workflow's most reachable trigger is `{}`".format(trigger.name),
        ]
        if trigger.outsider:
            notes.append("that trigger is reachable by any GitHub user, so any code "
                         "execution here inherits the token")
        title = ("GITHUB_TOKEN is broader than necessary"
                 if origin != "job" else
                 "GITHUB_TOKEN is broader than necessary in job `{}`".format(job_ids[0]))
        findings.append(Finding(
            rule_id=EXCESSIVE_PERMISSIONS.id,
            title=title,
            path=ctx.wf.path, line=line,
            job=job_ids[0] if len(job_ids) == 1 else None,
            message=message, evidence=evidence,
            remediation=EXCESSIVE_PERMISSIONS.remediation,
            references=EXCESSIVE_PERMISSIONS.references,
            tags=EXCESSIVE_PERMISSIONS.tags,
            factors=ScoreFactors(
                impact=IMPACT_HYGIENE,
                actor=trigger.actor if trigger.outsider else knowledge.ACTOR_WRITE,
                notes=notes,
            ),
            fingerprint_extra="permissions:" + origin,
        ))
    return findings


@rule
def secrets_with_untrusted_code(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if ctx.wf.kind == "action":
        return findings
    if not any(ctx.trigger(e).outsider and ctx.trigger(e).secrets
               for e in ctx.events):
        return findings
    for job in ctx.wf.jobs.values():
        uses_secret = False
        secret_line = job.pos.line
        for path, value in _iter_job_strings(job):
            from .. import expr
            for ref in expr.refs(value):
                if ref.root == "secrets" and ref.path != "secrets.GITHUB_TOKEN":
                    uses_secret = True
                    break
            if uses_secret:
                break
        if not uses_secret:
            continue
        checkout = next((s for s in job.steps if _checkout_of_untrusted_head(s)), None)
        if checkout is None:
            continue
        findings.append(Finding(
            rule_id=SECRETS_WITH_UNTRUSTED_CODE.id,
            title="Job `{}` exposes secrets to untrusted pull request code".format(job.id),
            path=ctx.wf.path, line=secret_line, job=job.id,
            message=SECRETS_WITH_UNTRUSTED_CODE.summary + ". Every process in the job can "
                    "read them, including anything the checked-out tree causes to run.",
            evidence=_checkout_of_untrusted_head(checkout) or "",
            remediation=SECRETS_WITH_UNTRUSTED_CODE.remediation,
            references=SECRETS_WITH_UNTRUSTED_CODE.references,
            tags=SECRETS_WITH_UNTRUSTED_CODE.tags,
            factors=ScoreFactors(
                impact=IMPACT_SECRETS_AND_WRITE,
                actor=worst_trigger(ctx.events, ctx).actor,
                guard=job_guard(job, None, ctx),
                notes=_note_guard(ctx, job, None,
                    ["job references a named secret and checks out the pull request head"]),
            ),
            fingerprint_extra="secrets-untrusted",
        ))
    return findings


@rule
def bulk_secret_exposure(ctx: Context) -> Iterable[Finding]:
    from .. import expr
    findings: List[Finding] = []
    pattern = re.compile(r"toJSON\(\s*secrets\s*\)", re.IGNORECASE)
    for job in ctx.wf.jobs.values():
        for path, value in _iter_job_strings(job):
            if not isinstance(value, str) or not pattern.search(value):
                continue
            findings.append(Finding(
                rule_id=SECRET_EXPOSURE.id,
                title="Every repository secret is serialised into job `{}`".format(job.id),
                path=ctx.wf.path, line=job.pos.line, job=job.id,
                message=_sentence(SECRET_EXPOSURE.summary) + " " + _sentence(SECRET_EXPOSURE.description, 1),
                evidence=value.strip()[:160],
                remediation=SECRET_EXPOSURE.remediation,
                references=SECRET_EXPOSURE.references,
                tags=SECRET_EXPOSURE.tags,
                factors=ScoreFactors(
                    impact=IMPACT_SECRETS_AND_WRITE * 0.7,
                    actor=worst_trigger(ctx.events, ctx).actor,
                    notes=["log masking only redacts exact matches of each secret"],
                ),
                fingerprint_extra="tojson-secrets",
            ))
            break
    return findings


_BOT_ACTOR_RE = re.compile(r"github\.(actor|triggering_actor)\s*==\s*'[^']*\[bot\]'")


@rule
def bot_identity_trust(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if "pull_request_target" not in ctx.events and "workflow_run" not in ctx.events:
        return findings
    for job in ctx.wf.jobs.values():
        condition = job.if_ or ""
        if not _BOT_ACTOR_RE.search(condition):
            continue
        findings.append(Finding(
            rule_id=BOT_ACTOR_TRUST.id,
            title="Job `{}` trusts a bot identity on a privileged trigger".format(job.id),
            path=ctx.wf.path, line=job.if_pos.line, job=job.id,
            message=_sentence(BOT_ACTOR_TRUST.summary) + " " + _sentence(BOT_ACTOR_TRUST.description, 1),
            evidence=condition.strip()[:160],
            remediation=BOT_ACTOR_TRUST.remediation,
            references=BOT_ACTOR_TRUST.references,
            tags=BOT_ACTOR_TRUST.tags,
            factors=ScoreFactors(
                impact=IMPACT_SECRETS_AND_WRITE * 0.8,
                actor=knowledge.ACTOR_ANY_APPROVED,
                notes=["an actor check does not constrain the contents of the diff"],
            ),
            fingerprint_extra="bot-actor",
        ))
    return findings


def _iter_job_strings(job: Job):
    from .. import expr
    return expr.iter_strings(job.raw)


def _note_guard(ctx, job, step, notes):
    """Append the `if:` gating explanation so the score is self-justifying."""
    description = guard_description(job, step, ctx)
    if description:
        notes.append("gated by an `if:` condition: " + description)
    return notes
