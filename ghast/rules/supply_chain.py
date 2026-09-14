"""Rules about code this repository executes but does not own."""
from __future__ import annotations

import re
from typing import Iterable, List, Optional

from .. import knowledge
from ..findings import (
    IMPACT_HYGIENE, IMPACT_RUNNER, IMPACT_SECRETS_AND_WRITE, Finding, RuleMeta,
    ScoreFactors, register, sentence as _sentence,
)
from ..model import Job, Step
from . import rule
from .base import (
    Context, effective_permissions, guard_description, job_guard, token_is_write,
    worst_trigger,
)

DOCS_PIN = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"
DOCS_ARTIFACT = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"

UNPINNED_ACTION = register(RuleMeta(
    id="GHAST020",
    name="unpinned-action",
    summary="A third-party action is referenced by a mutable ref",
    description=(
        "Tags and branches are pointers the action's owner can move at any time, and an "
        "attacker who takes over that account -- or simply retags -- changes what runs in "
        "this repository on the next execution. The action runs inside the job, so it sees "
        "every secret and token the job holds."
    ),
    remediation=(
        "Pin to the full commit SHA and keep the human-readable version in a comment:\n\n"
        "    - uses: owner/action@e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4  # v4.1.1\n\n"
        "Dependabot updates SHA pins if you enable the `github-actions` ecosystem."
    ),
    references=(DOCS_PIN,),
    tags=("supply-chain", "pinning"),
))

BRANCH_PINNED_ACTION = register(RuleMeta(
    id="GHAST021",
    name="branch-pinned-action",
    summary="A third-party action is referenced by a branch name",
    description=(
        "A branch reference re-resolves on every run, so whatever was pushed to that branch "
        "most recently executes here. There is no review step and no version to audit."
    ),
    remediation="Pin to the full commit SHA.",
    references=(DOCS_PIN,),
    tags=("supply-chain", "pinning"),
))

ARTIFACT_POISONING = register(RuleMeta(
    id="GHAST022",
    name="artifact-poisoning",
    summary="A privileged workflow consumes artifacts produced by an untrusted run",
    description=(
        "`workflow_run` fires after the unprivileged workflow that an outsider's pull "
        "request just ran, and artifacts from that run are entirely attacker-authored. "
        "Downloading and then reading, extracting or executing them inside a job that "
        "holds secrets hands over the job. Path traversal in archive entries can also "
        "write outside the extraction directory."
    ),
    remediation=(
        "Download into a directory of its own, outside the checkout, so a hostile archive "
        "cannot overwrite the scripts this job is about to run:\n\n"
        "    - uses: actions/download-artifact@<sha>\n"
        "      with:\n"
        "        path: ./untrusted-artifact\n"
        "        name: results\n\n"
        "Then treat the contents as hostile input: validate names and types before use, "
        "never execute, `source` or `eval` anything from them, and keep the privileged "
        "action in a step that only reads values you have already validated."
    ),
    references=(DOCS_ARTIFACT,),
    tags=("supply-chain", "pwn-request"),
))

CACHE_POISONING = register(RuleMeta(
    id="GHAST023",
    name="cache-poisoning",
    summary="A fork-triggered job writes to a cache that privileged jobs restore",
    description=(
        "Actions caches are scoped to a branch but fall back to the default branch, and a "
        "job running a fork pull request can create cache entries. A privileged workflow "
        "on the default branch that restores the same key can therefore be handed "
        "attacker-written files -- compiled artifacts, node_modules, toolchains -- which it "
        "then executes."
    ),
    remediation=(
        "Do not populate shared caches from fork pull request jobs. Use "
        "`actions/cache/restore` with `lookup-only`/read-only semantics in untrusted jobs, "
        "and include a trust boundary in the cache key."
    ),
    references=(DOCS_ARTIFACT,),
    tags=("supply-chain", "cache"),
))

DOCKER_UNPINNED = register(RuleMeta(
    id="GHAST024",
    name="unpinned-container",
    summary="A container image is referenced by a mutable tag",
    description=(
        "`docker://image:tag` and job `container:` tags are re-resolved on every run. The "
        "image contents can change without any change here."
    ),
    remediation="Reference the image by digest: `image@sha256:...`.",
    references=(DOCS_PIN,),
    tags=("supply-chain", "pinning"),
))


_BRANCHY = re.compile(r"^(main|master|develop|dev|trunk|latest|head|releases?/.+)$", re.I)
_VERSION_TAG = re.compile(r"^v?\d+(\.\d+)*(-[\w.]+)?$")


def _job_is_privileged(ctx: Context, job: Job) -> bool:
    trigger = worst_trigger(ctx.events)
    if not trigger.secrets:
        return False
    permissions, _ = effective_permissions(ctx.wf, job)
    return token_is_write(permissions) is not False


@rule
def unpinned_actions(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    trigger = worst_trigger(ctx.events) if ctx.wf.kind != "action" else knowledge.UNKNOWN_TRIGGER
    for job in ctx.wf.jobs.values():
        privileged = _job_is_privileged(ctx, job) if ctx.wf.kind != "action" else True
        for step in job.steps:
            uses = step.uses
            if uses is None:
                continue
            if uses.docker:
                if "@sha256:" not in uses.raw:
                    findings.append(_docker_finding(ctx, job, step, uses.raw))
                continue
            if uses.local or not uses.owner:
                continue
            if uses.is_sha_pinned:
                continue
            if uses.is_expression:
                continue  # covered by GHAST006
            first_party = uses.owner.lower() in knowledge.FIRST_PARTY_OWNERS
            ref = uses.ref or "(no ref)"
            branchy = bool(_BRANCHY.match(ref))
            meta = BRANCH_PINNED_ACTION if branchy else UNPINNED_ACTION

            impact = IMPACT_SECRETS_AND_WRITE if privileged else IMPACT_RUNNER
            impact *= 0.55 if first_party else 1.0
            if not branchy:
                impact *= 0.8   # a moved tag is at least conventionally reviewed

            notes = [
                "`{}` is a {}, which the action owner can repoint at any time".format(
                    ref, "branch" if branchy else "tag"),
            ]
            if first_party:
                notes.append("owner `{}` is maintained by GitHub, a materially smaller "
                             "risk than an arbitrary account".format(uses.owner))
            if privileged:
                notes.append("this job carries secrets or a write-scoped token")
            findings.append(Finding(
                rule_id=meta.id,
                title="`{}` is not pinned to a commit".format(uses.slug),
                path=ctx.wf.path, line=step.uses_pos.line, job=job.id, step=step.label,
                message=_sentence(meta.summary) + " " + _sentence(meta.description, 0),
                evidence="uses: " + uses.raw,
                remediation=meta.remediation,
                references=meta.references,
                tags=meta.tags,
                factors=ScoreFactors(
                    impact=impact,
                    actor=knowledge.ACTOR_WRITE,   # requires compromising the action owner
                    notes=notes,
                ),
                fingerprint_extra=uses.raw,
            ))
    return findings


def _docker_finding(ctx: Context, job: Job, step: Step, raw: str) -> Finding:
    return Finding(
        rule_id=DOCKER_UNPINNED.id,
        title="Container image `{}` is not pinned by digest".format(raw),
        path=ctx.wf.path, line=step.uses_pos.line, job=job.id, step=step.label,
        message=_sentence(DOCKER_UNPINNED.summary) + " " + DOCKER_UNPINNED.description,
        evidence="uses: " + raw,
        remediation=DOCKER_UNPINNED.remediation,
        references=DOCKER_UNPINNED.references,
        tags=DOCKER_UNPINNED.tags,
        factors=ScoreFactors(impact=IMPACT_HYGIENE * 1.4, actor=knowledge.ACTOR_WRITE,
                             notes=["image tags are mutable"]),
        fingerprint_extra=raw,
    )


#: Three distinct things can happen to a downloaded artifact, and they are not
#: equally bad.  Ranking them is the difference between a report a maintainer
#: acts on and one they mute.
#:
#: 1. the downloaded bytes are executed or sourced      -> certain compromise
#: 2. the download lands in the workspace, where it can overwrite the
#:    checked-out scripts a later step runs              -> likely compromise
#: 3. a trusted script merely reads it                   -> needs review
#:
#: Telling (1) from (3) needs the *path*, not just the verb: `node ./scripts/x.js`
#: runs a file from the checkout, while `node ./artifact/x.js` runs one the
#: attacker wrote.  Both are worth a line in a report; only one is a critical.

_SOURCES_FILE = re.compile(r"(^|[;&|]\s*)(source|\.)\s+(?P<path>\S+)", re.MULTILINE)
_INTERPRETS = re.compile(
    r"\b(bash|sh|zsh|node|python3?|ruby|perl|deno|dotnet|go\s+run)\s+(?P<path>[^\s;&|]+)")
_MAKES_EXECUTABLE = re.compile(r"\bchmod\s+\+x\s+(?P<path>\S+)")
_EVALS = re.compile(r"\beval\b")
_EXTRACTS = re.compile(
    r"\b(unzip|bsdtar|7z\s+x|jar\s+xf)\b|\btar\s+[^|;\n]*x", re.IGNORECASE)
_READS = re.compile(r"\b(cat|jq|grep|head|tail|node|python3?|ruby)\s+\S")

TIER_EXECUTES = "executes"
TIER_EXTRACTS = "extracts"
TIER_READS = "reads"


def _untrusted_tokens(download: Step, jobs_steps: List[Step]) -> List[str]:
    """Path fragments that identify attacker-written files in this job."""
    tokens: List[str] = []
    with_ = download.with_ or {}
    for key in ("path", "name"):
        value = str(with_.get(key, "")).strip().strip("./")
        if value and "${{" not in value:
            tokens.append(value.lower())
    # Wherever an archive was unpacked to is untrusted as well.
    for step in jobs_steps:
        if not step.run:
            continue
        for match in re.finditer(r"-(?:d|C|o)\s+(\S+)", step.run):
            target = match.group(1).strip().strip("./").lower()
            if target and not target.startswith("-"):
                tokens.append(target)
    return [t for t in dict.fromkeys(tokens) if len(t) > 2]


def _is_untrusted_path(path: str, tokens: List[str]) -> bool:
    """Does this path point *into* the downloaded artifact?

    Compared segment by segment, never as a substring: the artifact
    `preview-tarballs` must not make `scripts/upload-preview-tarballs.js`
    -- a file from the checkout -- look attacker-controlled.  (vercel/next.js
    was reported as a high because of exactly that bug.)
    """
    cleaned = path.strip().strip("\"'").lower().lstrip("./")
    segments = [seg for seg in cleaned.split("/") if seg not in ("", ".")]
    if not segments:
        return False
    for token in tokens:
        token_segments = [seg for seg in token.split("/") if seg not in ("", ".")]
        if not token_segments:
            continue
        if segments[:len(token_segments)] == token_segments:
            return True
        if len(token_segments) == 1 and token_segments[0] in segments[:-1]:
            return True
    return False


def _classify_consumption(step: Step, tokens: List[str]):
    """``(tier, match)`` for the first meaningful use of the download."""
    script = step.run or ""
    for match in _SOURCES_FILE.finditer(script):
        # Sourcing pulls the file's contents into the current shell. Even a
        # repo-owned path qualifies when the download can overwrite it.
        return TIER_EXECUTES, match
    match = _EVALS.search(script)
    if match:
        return TIER_EXECUTES, match
    for pattern in (_MAKES_EXECUTABLE, _INTERPRETS):
        for match in pattern.finditer(script):
            if _is_untrusted_path(match.group("path"), tokens):
                return TIER_EXECUTES, match
    match = _EXTRACTS.search(script)
    if match:
        return TIER_EXTRACTS, match
    for pattern in (_INTERPRETS, _READS):
        match = pattern.search(script)
        if match:
            return TIER_READS, match
    return None, None


@rule
def artifact_poisoning(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if "workflow_run" not in ctx.events:
        return findings
    for job in ctx.wf.jobs.values():
        download: Optional[Step] = None
        for step in job.steps:
            slug = (step.uses.full_path or "").lower() if step.uses else ""
            if any(slug == a for a in knowledge.ARTIFACT_DOWNLOAD_ACTIONS):
                download = step
                break
            if step.run and "gh run download" in step.run:
                download = step
                break
        if download is None:
            continue

        # Where does the artifact land?  With no `path:`, it lands in the
        # workspace and can overwrite files the checkout just placed there.
        download_path = str((download.with_ or {}).get("path", "")).strip()
        isolated = bool(download_path) and not download_path.startswith((".", "$GITHUB_WORKSPACE"))
        later = [s for s in job.steps if s.index > download.index]
        tokens = _untrusted_tokens(download, later)

        consumer: Optional[Step] = None
        consumer_line = 0
        consumer_text = ""
        tier = None
        for step in later:
            found_tier, match = _classify_consumption(step, tokens)
            if found_tier is None:
                continue
            consumer, tier = step, found_tier
            base = step.run_pos.line
            if re.search(r"run\s*:\s*[|>][-+0-9]*\s*$", ctx.wf.line_text(base)):
                base += 1
            offset_line = (step.run or "").count("\n", 0, match.start())
            consumer_line = base + offset_line
            consumer_text = (step.run or "").splitlines()[offset_line].strip()
            break

        notes = [
            "`workflow_run` runs with repository secrets after an unprivileged run finishes",
            "artifacts from that run are written by the pull request author",
        ]
        impact = IMPACT_SECRETS_AND_WRITE
        confidence = "certain"
        if consumer is None:
            impact *= 0.55
            confidence = "likely"
            notes.append("nothing in this job was seen consuming the download, so "
                         "exploitability depends on what reads it later")
        elif tier == TIER_EXECUTES:
            notes.append("step `{}` executes or sources content from the download"
                         .format(consumer.label))
        elif tier == TIER_EXTRACTS:
            impact *= 0.85
            notes.append("step `{}` extracts the archive; entry names are chosen by the "
                         "attacker".format(consumer.label))
        else:
            impact *= 0.7
            confidence = "likely"
            notes.append("step `{}` reads the download using a script from this repository, "
                         "so exploitability depends on what that script does"
                         .format(consumer.label))
        if isolated:
            impact *= 0.8
            notes.append("the download is isolated in `{}`, away from the checkout"
                         .format(download_path))
        else:
            notes.append("no `path:` was set on the download, so it unpacks into the "
                         "workspace and can overwrite the files the checkout placed there")
        _note_guard(ctx, job, None, notes)

        findings.append(Finding(
            rule_id=ARTIFACT_POISONING.id,
            title="Privileged `workflow_run` job consumes untrusted artifacts",
            path=ctx.wf.path, line=consumer_line or download.pos.line,
            job=job.id, step=(consumer or download).label,
            message=_sentence(ARTIFACT_POISONING.summary) + " " +
                    _sentence(ARTIFACT_POISONING.description, 1),
            evidence=consumer_text or (
                download.uses.raw if download.uses else
                (download.run or "").strip().splitlines()[0][:160]),
            remediation=ARTIFACT_POISONING.remediation,
            references=ARTIFACT_POISONING.references,
            tags=ARTIFACT_POISONING.tags,
            factors=ScoreFactors(impact=impact, actor=knowledge.ACTOR_ANY,
                                 guard=job_guard(job, None, ctx), confidence=confidence,
                                 notes=notes),
            fingerprint_extra="artifact",
        ))
    return findings


@rule
def cache_poisoning(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    if "pull_request" not in ctx.events:
        return findings
    # A workflow that only ever runs on fork PRs is where poisoning originates.
    for job in ctx.wf.jobs.values():
        for step in job.steps:
            full = (step.uses.full_path or "").lower() if step.uses else ""
            if not any(full == c or full.startswith(c + "/") for c in knowledge.CACHE_ACTIONS):
                continue
            with_ = step.with_ or {}
            read_only = str(with_.get("lookup-only", "")).lower() == "true"
            # `actions/cache/restore` only reads; it cannot poison anything.
            if read_only or full.endswith("/restore"):
                continue
            key = str(with_.get("key", ""))
            notes = [
                "this job runs for pull requests, including from forks",
                "cache entries created here are visible to default-branch workflows "
                "through the cache fallback rules",
            ]
            if "github.head_ref" in key or "github.ref" in key:
                notes.append("the cache key includes a ref, which narrows but does not "
                             "close the fallback path")
            _note_guard(ctx, job, None, notes)
            findings.append(Finding(
                rule_id=CACHE_POISONING.id,
                title="Fork-triggered job populates a shared Actions cache",
                path=ctx.wf.path, line=step.uses_pos.line, job=job.id, step=step.label,
                message=_sentence(CACHE_POISONING.summary) + " " +
                        _sentence(CACHE_POISONING.description, 1),
                evidence="uses: {}{}".format(step.uses.raw if step.uses else "",
                                             "  key: " + key if key else ""),
                remediation=CACHE_POISONING.remediation,
                references=CACHE_POISONING.references,
                tags=CACHE_POISONING.tags,
                factors=ScoreFactors(impact=IMPACT_RUNNER * 1.2,
                                     actor=knowledge.ACTOR_ANY,
                                     confidence="likely",
                                     guard=job_guard(job, None, ctx), notes=notes),
                fingerprint_extra="cache",
            ))
    return findings


def _note_guard(ctx, job, step, notes):
    """Append the `if:` gating explanation so the score is self-justifying."""
    description = guard_description(job, step, ctx)
    if description:
        notes.append("gated by an `if:` condition: " + description)
    return notes
