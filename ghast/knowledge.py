"""The security model: what an attacker controls, and what that buys them.

Everything here is a deliberate, reviewable claim about GitHub's execution
model.  Rules are thin; this table is where the thinking lives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple


# --------------------------------------------------------------------------
# Who has to be the attacker
# --------------------------------------------------------------------------

#: Anyone with a GitHub account.  No relationship to the repository needed.
ACTOR_ANY = "any-github-user"
#: Someone who has to get a maintainer to do something (approve a workflow run).
ACTOR_ANY_APPROVED = "any-user-after-approval"
#: Someone with push access.  Insider threat / compromised maintainer account.
ACTOR_WRITE = "write-access"

_ACTOR_RANK = {ACTOR_ANY: 3, ACTOR_ANY_APPROVED: 2, ACTOR_WRITE: 1}


def actor_rank(actor: str) -> int:
    return _ACTOR_RANK.get(actor, 1)


# --------------------------------------------------------------------------
# Attacker-controlled context paths
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    path: str
    actor: str
    note: str
    #: Charset is effectively unrestricted -> shell metacharacters get through.
    freeform: bool = True


def _s(path: str, actor: str, note: str, freeform: bool = True) -> Tuple[str, Source]:
    return path, Source(path, actor, note, freeform)


#: Paths whose *value* an outsider can choose.  Anything not listed here is
#: treated as untainted, so additions are the main way to reduce false
#: negatives.  Deliberately excluded: logins, SHAs, numeric ids and other
#: values GitHub constrains to a safe charset.
SOURCES: Dict[str, Source] = dict(
    [
        # --- issues & comments: no repo relationship required at all ---
        _s("github.event.issue.title", ACTOR_ANY, "issue title, chosen by the reporter"),
        _s("github.event.issue.body", ACTOR_ANY, "issue body, chosen by the reporter"),
        _s("github.event.comment.body", ACTOR_ANY, "comment body"),
        _s("github.event.discussion.title", ACTOR_ANY, "discussion title"),
        _s("github.event.discussion.body", ACTOR_ANY, "discussion body"),
        # --- pull requests: anyone may open one from a fork ---
        _s("github.event.pull_request.title", ACTOR_ANY, "PR title"),
        _s("github.event.pull_request.body", ACTOR_ANY, "PR body"),
        _s("github.event.pull_request.head.ref", ACTOR_ANY,
           "source branch name; git allows shell metacharacters here"),
        _s("github.event.pull_request.head.label", ACTOR_ANY, "owner:branch of the PR head"),
        _s("github.event.pull_request.head.repo.description", ACTOR_ANY, "fork description"),
        _s("github.event.pull_request.head.repo.homepage", ACTOR_ANY, "fork homepage URL"),
        _s("github.event.pull_request.head.repo.default_branch", ACTOR_ANY,
           "fork default branch name"),
        _s("github.head_ref", ACTOR_ANY, "alias of pull_request.head.ref"),
        _s("github.event.review.body", ACTOR_ANY, "PR review body"),
        _s("github.event.review_comment.body", ACTOR_ANY, "PR review comment body"),
        # --- commit metadata: attacker-authored on any fork PR or workflow_run ---
        _s("github.event.commits.*.message", ACTOR_ANY, "commit message"),
        _s("github.event.commits.*.author.name", ACTOR_ANY, "commit author name"),
        _s("github.event.commits.*.author.email", ACTOR_ANY, "commit author email"),
        _s("github.event.head_commit.message", ACTOR_ANY, "head commit message"),
        _s("github.event.head_commit.author.name", ACTOR_ANY, "head commit author name"),
        _s("github.event.head_commit.author.email", ACTOR_ANY, "head commit author email"),
        _s("github.event.head_commit.committer.name", ACTOR_ANY, "head commit committer name"),
        _s("github.event.head_commit.committer.email", ACTOR_ANY, "head commit committer email"),
        # --- workflow_run: carries the *upstream* workflow's attacker data ---
        _s("github.event.workflow_run.head_branch", ACTOR_ANY,
           "branch of the run that triggered this one"),
        _s("github.event.workflow_run.display_title", ACTOR_ANY, "title of the upstream run"),
        _s("github.event.workflow_run.head_commit.message", ACTOR_ANY,
           "commit message from the upstream run"),
        _s("github.event.workflow_run.pull_requests.*.head.ref", ACTOR_ANY,
           "head branch of the PR behind the upstream run"),
        # --- pages ---
        _s("github.event.pages.*.page_name", ACTOR_ANY, "wiki page name"),
        _s("github.event.pages.*.title", ACTOR_ANY, "wiki page title"),
        # --- requires write access: insider / account-takeover reach ---
        _s("github.event.release.body", ACTOR_WRITE, "release notes"),
        _s("github.event.release.tag_name", ACTOR_WRITE, "release tag"),
        _s("github.event.release.name", ACTOR_WRITE, "release name"),
        _s("github.event.milestone.title", ACTOR_WRITE, "milestone title"),
        _s("github.event.milestone.description", ACTOR_WRITE, "milestone description"),
        _s("github.event.inputs.*", ACTOR_WRITE, "workflow_dispatch input"),
        _s("inputs.*", ACTOR_WRITE, "workflow_dispatch / workflow_call input"),
        _s("github.event.client_payload.*", ACTOR_WRITE, "repository_dispatch payload"),
    ]
)


def match_source(path: str) -> Optional[Source]:
    """Longest-prefix lookup: ``...issue.body.foo`` is still the issue body."""
    best: Optional[Source] = None
    for key, src in SOURCES.items():
        if key.endswith(".*"):
            stem = key[:-2]
            if path == stem or path.startswith(stem + "."):
                if best is None or len(key) > len(best.path):
                    best = src
            continue
        if path == key or path.startswith(key + "."):
            if best is None or len(key) > len(best.path):
                best = src
    return best


# --------------------------------------------------------------------------
# Trigger privilege model
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Trigger:
    name: str
    #: Repository secrets are readable by jobs in this workflow.
    secrets: bool
    #: GITHUB_TOKEN is write-scoped unless `permissions:` narrows it.
    token_write: bool
    #: An outsider can cause this event without any repo permission.
    outsider: bool
    #: Who has to act.
    actor: str
    note: str


def _t(name: str, secrets: bool, token_write: bool, outsider: bool, actor: str, note: str):
    return name, Trigger(name, secrets, token_write, outsider, actor, note)


TRIGGERS: Dict[str, Trigger] = dict(
    [
        _t("pull_request_target", True, True, True, ACTOR_ANY,
           "runs against the base repo with full secrets while carrying fork-authored data"),
        _t("issue_comment", True, True, True, ACTOR_ANY,
           "any user can comment on any public issue or PR"),
        _t("issues", True, True, True, ACTOR_ANY, "any user can open an issue"),
        _t("discussion", True, True, True, ACTOR_ANY, "any user can open a discussion"),
        _t("discussion_comment", True, True, True, ACTOR_ANY, "any user can comment"),
        _t("pull_request_review", True, True, True, ACTOR_ANY, "any user can review a PR"),
        _t("pull_request_review_comment", True, True, True, ACTOR_ANY,
           "any user can comment on a PR diff"),
        _t("workflow_run", True, True, True, ACTOR_ANY,
           "privileged, and fires after an unprivileged workflow the attacker influenced"),
        _t("fork", True, True, True, ACTOR_ANY, "any user can fork"),
        _t("watch", True, True, True, ACTOR_ANY, "any user can star"),
        _t("gollum", True, True, True, ACTOR_ANY, "wiki edits may be open to any user"),
        # fork PRs get a read-only token and no secrets, but still execute on the runner
        _t("pull_request", False, False, True, ACTOR_ANY,
           "fork PRs run with a read-only token and no secrets, but do execute on the runner"),
        _t("pull_request_review_comment_target", True, True, True, ACTOR_ANY, "target variant"),
        # privileged-only triggers
        _t("push", True, True, False, ACTOR_WRITE, "requires push access"),
        _t("create", True, True, False, ACTOR_WRITE, "requires push access"),
        _t("delete", True, True, False, ACTOR_WRITE, "requires push access"),
        _t("release", True, True, False, ACTOR_WRITE, "requires release permission"),
        _t("milestone", True, True, False, ACTOR_WRITE, "requires triage permission"),
        _t("schedule", True, True, False, ACTOR_WRITE, "not externally triggerable"),
        _t("workflow_dispatch", True, True, False, ACTOR_WRITE, "requires write access"),
        _t("repository_dispatch", True, True, False, ACTOR_WRITE, "requires a token with write"),
        _t("workflow_call", True, True, False, ACTOR_WRITE, "inherits the caller's context"),
        _t("registry_package", True, True, False, ACTOR_WRITE, "requires package write"),
        _t("deployment", True, True, False, ACTOR_WRITE, "requires deployment permission"),
        _t("deployment_status", True, True, False, ACTOR_WRITE, "requires deployment permission"),
        _t("status", True, True, False, ACTOR_WRITE, "requires write access"),
        _t("label", True, True, False, ACTOR_WRITE, "requires triage permission"),
        _t("project", True, True, False, ACTOR_WRITE, "requires write access"),
        _t("page_build", True, True, False, ACTOR_WRITE, "follows a push"),
        _t("merge_group", True, True, False, ACTOR_WRITE, "merge queue"),
    ]
)

UNKNOWN_TRIGGER = Trigger("unknown", True, True, False, ACTOR_WRITE, "unrecognised event")


def trigger(name: str) -> Trigger:
    return TRIGGERS.get(name, UNKNOWN_TRIGGER)


#: Events where the *workflow file itself* comes from the default branch, so an
#: attacker cannot edit the workflow — only feed data into it.
BASE_REF_EVENTS: FrozenSet[str] = frozenset(
    {
        "pull_request_target", "issue_comment", "issues", "discussion",
        "discussion_comment", "pull_request_review", "pull_request_review_comment",
        "workflow_run", "fork", "watch", "gollum", "schedule", "label", "milestone",
    }
)


# --------------------------------------------------------------------------
# Sinks and supply-chain facts
# --------------------------------------------------------------------------

#: Action inputs that are executed as code rather than consumed as data.
CODE_EXECUTING_INPUTS: Dict[str, Tuple[str, ...]] = {
    "actions/github-script": ("script",),
    "cardinalby/js-eval-action": ("expression",),
    "actions/heroku": ("command",),
    "appleboy/ssh-action": ("script", "command"),
    "azure/cli": ("inlineScript",),
    "azure/powershell": ("inlineScript",),
    "google-github-actions/ssh-compute": ("command",),
    "peter-evans/create-or-update-comment": (),  # data sink, handled elsewhere
}

#: Environment variables that turn "I can set an env var" into "I run code".
CODE_LOADING_ENV_VARS: FrozenSet[str] = frozenset(
    {
        "NODE_OPTIONS", "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH", "PATH", "PYTHONPATH", "PYTHONSTARTUP", "PERL5LIB",
        "PERL5OPT", "RUBYOPT", "RUBYLIB", "BASH_ENV", "ENV", "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF", "GEM_PATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
    }
)

#: Third-party providers whose runners are destroyed after every job.  The
#: persistence argument behind the self-hosted rule does not apply to them:
#: there is nothing for an attacker to leave behind.  They are still someone
#: else's infrastructure in your build path, but calling them "self-hosted"
#: produces a wall of false criticals on repositories doing something sensible.
EPHEMERAL_RUNNER_PREFIXES: Tuple[str, ...] = (
    "blacksmith-", "blacksmith", "warp-", "depot-", "namespace-profile-",
    "nscloud-", "buildjet-", "ubicloud-", "ubicloud", "runs-on-", "actuated-",
    "cirun-", "hosted-", "codebuild-", "sprinters-",
)

#: Third-party managed runners that are *not* advertised as per-job ephemeral.
#: CodSpeed's macro runners, for instance, are dedicated bare-metal machines
#: whose entire purpose is hardware consistency between runs -- which argues
#: against tearing them down. Whether state survives is the provider's
#: business and is not visible in the workflow file, so ghast reports these
#: rather than silently clearing them, and says plainly what it does not know.
THIRD_PARTY_RUNNER_PREFIXES: Tuple[str, ...] = (
    "codspeed-", "codspeed",
)

#: Prefixes GitHub itself uses, including the larger-runner naming convention.
HOSTED_RUNNER_PREFIXES: Tuple[str, ...] = (
    "ubuntu-", "windows-", "macos-", "ubuntu_", "macos_", "windows_",
)

RUNNER_HOSTED = "hosted"
RUNNER_EPHEMERAL = "ephemeral-managed"
RUNNER_THIRD_PARTY = "third-party-managed"
RUNNER_SELF_HOSTED = "self-hosted"


def _clean_label(label: str) -> str:
    return label.strip().strip("\"'").lower()


def classify_runner_label(label: str) -> str:
    low = _clean_label(label)
    if low == "self-hosted":
        return RUNNER_SELF_HOSTED
    if any(low.startswith(p) for p in HOSTED_RUNNER_PREFIXES):
        return RUNNER_HOSTED
    if any(low.startswith(p) for p in EPHEMERAL_RUNNER_PREFIXES):
        return RUNNER_EPHEMERAL
    if any(low.startswith(p) for p in THIRD_PARTY_RUNNER_PREFIXES):
        return RUNNER_THIRD_PARTY
    return RUNNER_SELF_HOSTED


def is_managed_runner_label(label: str) -> bool:
    return classify_runner_label(label) in (RUNNER_EPHEMERAL, RUNNER_THIRD_PARTY)


def is_hosted_runner_label(label: str) -> bool:
    return classify_runner_label(label) == RUNNER_HOSTED


#: Owners whose actions are maintained by GitHub itself.  Still worth pinning,
#: but a floating tag here is a materially smaller risk than a random account.
FIRST_PARTY_OWNERS: FrozenSet[str] = frozenset({"actions", "github"})

#: Commands that hand control to the *checked-out tree*.
#:
#: The distinction that matters is whether the command's behaviour is decided
#: by files in the working directory or by an argument on the command line.
#: `npm ci` runs whatever lifecycle scripts package.json declares, so a hostile
#: checkout owns the runner.  `npm install -g some-pinned-package` does not:
#: it installs a named package from the registry and never reads the tree.
#: Conflating the two produces confident, wrong criticals.

_FLAG = re.compile(r"^-")


def _first_positional(rest: str) -> Optional[str]:
    for token in rest.split():
        if _FLAG.match(token):
            continue
        return token
    return None


_NODE_PM = re.compile(r"\b(npm|pnpm|bun|yarn)\s+(ci|install|i|add|run|test|start|build)\b"
                      r"(?P<rest>[^\n;&|]*)")
_YARN_BARE = re.compile(r"(^|[;&|]\s*)yarn\s*(--\S+\s*)*($|[;&|\n])")
_PIP = re.compile(r"\b(pip3?|uv\s+pip)\s+install\b(?P<rest>[^\n;&|]*)")
_ALWAYS_TREE = (
    (re.compile(r"(^|[;&|\s])make(\s|$)"), "make"),
    (re.compile(r"\./gradlew\b"), "./gradlew"),
    (re.compile(r"\bgradle\s+\w"), "gradle"),
    (re.compile(r"\bmvn\s+\w"), "mvn"),
    (re.compile(r"\bcargo\s+(build|test|run|bench|install\s+--path)\b"), "cargo"),
    (re.compile(r"\bgo\s+(generate|test|build|run)\b"), "go"),
    (re.compile(r"\bbundle\s+(install|exec)\b"), "bundle"),
    (re.compile(r"\bcomposer\s+install\b"), "composer install"),
    (re.compile(r"\b(python3?\s+)?setup\.py\b"), "setup.py"),
    (re.compile(r"\b(tox|nox|rake|pytest|jest|vitest)\b"), "test runner"),
    (re.compile(r"\bpoetry\s+install\b"), "poetry install"),
    (re.compile(r"\bdocker\s+(build|compose\s+(up|build|run))\b"), "docker build"),
    (re.compile(r"\bpre-commit\s+run\b"), "pre-commit"),
)


def detect_repo_code_execution(script: str) -> Optional[str]:
    """The command that lets the checked-out tree run code, if there is one."""
    if not script:
        return None
    for match in _NODE_PM.finditer(script):
        tool, verb = match.group(1), match.group(2)
        rest = match.group("rest") or ""
        if verb in ("run", "test", "start", "build"):
            return "{} {}".format(tool, verb)
        positional = _first_positional(rest)
        if positional is None or positional in (".", "./"):
            # No package named: the tree's manifest decides what happens.
            return "{} {}".format(tool, verb)
        # An explicitly named package is fetched from a registry, not the tree.
    if _YARN_BARE.search(script):
        return "yarn"
    for match in _PIP.finditer(script):
        rest = match.group("rest") or ""
        tokens = rest.split()
        if any(t in ("-r", "--requirement", "-e", "--editable") for t in tokens):
            return "pip install -r/-e"
        positional = _first_positional(rest)
        if positional in (".", "./", None):
            return "pip install ."
    for pattern, label in _ALWAYS_TREE:
        if pattern.search(script):
            return label
    return None


#: Kept for callers that only need the coarse list.
UNTRUSTED_CODE_STEP_PATTERNS = (
    "npm ci", "npm install", "yarn install", "pnpm install", "bundle install",
    "pip install", "make ", "./gradlew", "mvn ", "cargo build", "go generate",
    "composer install", "setup.py",
)

#: Actions that download artifacts produced by a different (possibly
#: attacker-controlled) workflow run.
ARTIFACT_DOWNLOAD_ACTIONS = (
    "actions/download-artifact",
    "dawidd6/action-download-artifact",
    "aochmann/actions-download-artifact",
)

CACHE_ACTIONS = ("actions/cache", "actions/cache/restore", "swatinem/rust-cache",
                 "buildjet/cache", "gradle/gradle-build-action", "gradle/actions/setup-gradle")

CHECKOUT_ACTIONS = ("actions/checkout",)

#: Refs that resolve to attacker-authored code in a privileged context.
PR_HEAD_REF_MARKERS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.merge_commit_sha",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.head_ref",
    "refs/pull/",
)


# --------------------------------------------------------------------------
# Which events actually populate which payload paths
# --------------------------------------------------------------------------

#: ``github.event.issue.title`` only exists when an issue event fired.  Without
#: this table every workflow that merely *mentions* a payload path would be
#: reported, which is the single biggest source of noise in tools of this kind.
PAYLOAD_EVENTS: Tuple[Tuple[str, FrozenSet[str]], ...] = (
    ("github.event.issue", frozenset({"issues", "issue_comment"})),
    ("github.event.comment", frozenset({"issue_comment", "pull_request_review_comment",
                                        "commit_comment", "discussion_comment"})),
    ("github.event.pull_request", frozenset({"pull_request", "pull_request_target",
                                             "pull_request_review",
                                             "pull_request_review_comment"})),
    ("github.head_ref", frozenset({"pull_request", "pull_request_target",
                                   "pull_request_review", "pull_request_review_comment"})),
    ("github.event.review", frozenset({"pull_request_review"})),
    ("github.event.discussion", frozenset({"discussion", "discussion_comment"})),
    ("github.event.commits", frozenset({"push"})),
    ("github.event.head_commit", frozenset({"push"})),
    ("github.event.workflow_run", frozenset({"workflow_run"})),
    ("github.event.pages", frozenset({"gollum"})),
    ("github.event.release", frozenset({"release"})),
    ("github.event.milestone", frozenset({"milestone"})),
    ("github.event.inputs", frozenset({"workflow_dispatch"})),
    ("inputs", frozenset({"workflow_dispatch", "workflow_call"})),
    ("github.event.client_payload", frozenset({"repository_dispatch"})),
)


def events_for_path(path: str) -> Optional[FrozenSet[str]]:
    """Events that populate ``path``; ``None`` when we have no opinion."""
    best: Optional[FrozenSet[str]] = None
    best_len = -1
    for prefix, events in PAYLOAD_EVENTS:
        if (path == prefix or path.startswith(prefix + ".")) and len(prefix) > best_len:
            best, best_len = events, len(prefix)
    return best
