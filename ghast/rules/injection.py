"""Rules derived from taint sinks: the attacker's data reached something that
interprets it."""
from __future__ import annotations

from typing import Dict, Iterable, List

from ..findings import (
    IMPACT_ARGUMENT, Finding, RuleMeta, ScoreFactors, register,
    sentence as _sentence,
)
from ..taint import (
    SINK_ACTION_INPUT, SINK_ENV_FILE, SINK_RUN_ENV_ARG, SINK_RUN_ENV_EXEC,
    SINK_RUN_INTERPOLATION, SINK_SCRIPT_INPUT, SINK_USES_REF, SinkHit,
)
from . import rule
from .base import Context, factors_for_flow

DOCS_INJECTION = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"
DOCS_ENVFILE = "https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#environment-files"

TEMPLATE_INJECTION = register(RuleMeta(
    id="GHAST001",
    name="template-injection",
    summary="Attacker-controlled value is substituted into a shell script",
    description=(
        "GitHub expands `${{ ... }}` by pasting the value into the script *as text* "
        "before any shell parses it. Quoting in the YAML does not help: the attacker's "
        "content becomes part of the program. Any value an outsider can choose -- an "
        "issue title, a comment body, a fork's branch name -- therefore becomes "
        "arbitrary command execution with whatever the job can reach."
    ),
    remediation=(
        "Pass the value through the environment instead of interpolating it, and quote "
        "the read:\n\n"
        "    - env:\n"
        "        TITLE: ${{ github.event.issue.title }}\n"
        "      run: echo \"$TITLE\"\n\n"
        "The environment carries the value as data, so the shell never re-parses it."
    ),
    references=(DOCS_INJECTION,),
    tags=("injection", "rce"),
))

SCRIPT_INPUT_INJECTION = register(RuleMeta(
    id="GHAST002",
    name="script-input-injection",
    summary="Attacker-controlled value reaches an action input that is executed as code",
    description=(
        "Some actions treat an input as a program rather than as data -- most commonly "
        "`actions/github-script`, whose `script:` input is evaluated as JavaScript with "
        "an authenticated Octokit client in scope. Interpolating attacker text into it "
        "is equivalent to interpolating into a shell."
    ),
    remediation=(
        "Move the value into the action's `env:` and read it from `process.env` inside "
        "the script:\n\n"
        "    - uses: actions/github-script@<sha>\n"
        "      env:\n"
        "        BODY: ${{ github.event.comment.body }}\n"
        "      with:\n"
        "        script: |\n"
        "          const body = process.env.BODY\n"
    ),
    references=(DOCS_INJECTION,),
    tags=("injection", "rce"),
))

ENV_FILE_INJECTION = register(RuleMeta(
    id="GHAST003",
    name="environment-file-injection",
    summary="Attacker-controlled value is appended to $GITHUB_ENV or $GITHUB_PATH",
    description=(
        "The runner reads `$GITHUB_ENV` and `$GITHUB_PATH` line by line after the step "
        "finishes. A newline inside the value therefore does not stay inside the value: "
        "it starts a new assignment. An attacker who controls any part of what is written "
        "can define arbitrary variables for every later step in the job, and variables "
        "like `NODE_OPTIONS`, `LD_PRELOAD`, `BASH_ENV` and `PATH` turn that into code "
        "execution without ever touching a `run:` block."
    ),
    remediation=(
        "Use the delimited form with a delimiter the attacker cannot guess, and prefer "
        "step outputs over environment variables when the value is untrusted:\n\n"
        "    DELIM=\"ghadelim_$(openssl rand -hex 16)\"\n"
        "    { echo \"BODY<<$DELIM\"; echo \"$RAW\"; echo \"$DELIM\"; } >> \"$GITHUB_ENV\"\n\n"
        "Better still, do not put untrusted data in the environment at all."
    ),
    references=(DOCS_ENVFILE,),
    tags=("injection", "rce", "privilege-escalation"),
))

ENV_EXEC = register(RuleMeta(
    id="GHAST004",
    name="tainted-variable-executed",
    summary="A variable holding attacker-controlled data is re-parsed as a command",
    description=(
        "Routing untrusted input through the environment is the right shape, but it only "
        "works if the value is never handed back to a parser. `eval \"$VAR\"`, "
        "`bash -c \"$VAR\"`, and a bare `$VAR` in command position all re-parse the "
        "contents as code and undo the protection."
    ),
    remediation=(
        "Never pass untrusted variables to `eval`, `sh -c`, or command position. If you "
        "need to branch on the value, compare it (`case`/`if`) against a fixed allow-list."
    ),
    references=(DOCS_INJECTION,),
    tags=("injection", "rce"),
))

ENV_ARG = register(RuleMeta(
    id="GHAST005",
    name="tainted-variable-unquoted",
    summary="Unquoted expansion of attacker-controlled data allows argument injection",
    description=(
        "An unquoted `$VAR` is split on whitespace and glob-expanded, so the attacker "
        "chooses additional arguments to the command. This is not direct code execution, "
        "but flags like `curl -o`, `git --upload-pack`, `rsync -e` and `tar --to-command` "
        "get most of the way there."
    ),
    remediation="Quote the expansion: `\"$VAR\"`.",
    references=(DOCS_INJECTION,),
    tags=("injection", "argument-injection"),
))

USES_REF_INJECTION = register(RuleMeta(
    id="GHAST006",
    name="attacker-controlled-action-reference",
    summary="The `uses:` reference itself is attacker-controlled",
    description=(
        "When `uses:` contains an expression fed by untrusted data, the attacker chooses "
        "which code the runner fetches and executes. This is the most direct form of "
        "workflow compromise available."
    ),
    remediation="Pin `uses:` to a literal `owner/repo@<40-char-sha>`; never build it from an expression.",
    references=(DOCS_INJECTION,),
    tags=("injection", "supply-chain", "rce"),
))

ACTION_INPUT_TAINT = register(RuleMeta(
    id="GHAST007",
    name="tainted-third-party-action-input",
    summary="Attacker-controlled value is passed to a third-party action",
    description=(
        "The value reaches an action whose implementation is outside this repository. "
        "Whether that is exploitable depends on what the action does with the input; "
        "actions that shell out, render templates, or build URLs frequently are."
    ),
    remediation=(
        "Review what the action does with this input. If it is only ever displayed, this "
        "is fine; if it reaches a shell, a template engine, or an HTTP request, treat it "
        "as an injection sink."
    ),
    references=(DOCS_INJECTION,),
    tags=("injection", "supply-chain"),
))


_META_FOR_SINK: Dict[str, RuleMeta] = {
    SINK_RUN_INTERPOLATION: TEMPLATE_INJECTION,
    SINK_SCRIPT_INPUT: SCRIPT_INPUT_INJECTION,
    SINK_ENV_FILE: ENV_FILE_INJECTION,
    SINK_RUN_ENV_EXEC: ENV_EXEC,
    SINK_RUN_ENV_ARG: ENV_ARG,
    SINK_USES_REF: USES_REF_INJECTION,
    SINK_ACTION_INPUT: ACTION_INPUT_TAINT,
}


def _title_for(hit: SinkHit) -> str:
    meta = _META_FOR_SINK[hit.kind]
    return "{} reaches {}".format(hit.flow.path, _sink_phrase(hit))


def _sink_phrase(hit: SinkHit) -> str:
    if hit.kind == SINK_RUN_INTERPOLATION:
        return "a `run:` script"
    if hit.kind == SINK_SCRIPT_INPUT:
        return "`{}`".format(hit.target)
    if hit.kind == SINK_ENV_FILE:
        return "`${}`".format(hit.target)
    if hit.kind in (SINK_RUN_ENV_EXEC, SINK_RUN_ENV_ARG):
        return "`{}`".format(hit.target)
    if hit.kind == SINK_USES_REF:
        return "a `uses:` reference"
    return "`{}`".format(hit.target)


@rule
def taint_sinks(ctx: Context) -> Iterable[Finding]:
    findings: List[Finding] = []
    seen = set()
    for hit in ctx.engine.sinks:
        meta = _META_FOR_SINK.get(hit.kind)
        if meta is None:
            continue
        impact = IMPACT_ARGUMENT if hit.kind == SINK_RUN_ENV_ARG else None
        factors = factors_for_flow(ctx, hit.job, hit.step, hit.flow, impact=impact)
        if hit.kind == SINK_ACTION_INPUT:
            # We cannot see inside the third-party action, so we do not know
            # whether this input reaches a parser at all.  Report it as a lead
            # to review, not as a vulnerability.
            factors.confidence = "speculative"
            factors.impact *= 0.5
            factors.notes.append(
                "the action's source was not analysed, so this is a lead to review "
                "rather than a confirmed sink")
        key = (meta.id, hit.job.id, hit.line, hit.target, hit.flow.path)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                rule_id=meta.id,
                title=_title_for(hit),
                path=ctx.wf.path,
                line=hit.line,
                job=hit.job.id,
                step=hit.step.label if hit.step else None,
                message="{} {}".format(_sentence(meta.summary), hit.detail),
                evidence=hit.evidence,
                remediation=meta.remediation,
                flow=hit.flow.chain,
                references=meta.references,
                tags=meta.tags,
                factors=factors,
                fingerprint_extra=hit.flow.path + "|" + hit.target,
            )
        )
    return findings
