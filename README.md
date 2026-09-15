# ghast

**Taint-analysis security scanner for GitHub Actions workflows.**

`ghast` traces attacker-controlled data — an issue title, a comment body, a fork's
branch name — from where it enters a workflow to where something *interprets* it, and
tells you what an attacker gets if they follow that path.

It is not a linter. The interesting bugs in CI are not visible one `run:` block at a
time, because attacker data usually travels:

```
github.event.issue.title
  → job env: TITLE
  → echo "slug=$TITLE" >> $GITHUB_OUTPUT      (step output)
  → needs.prepare.outputs.slug                (another job entirely)
  → run: ./deploy.sh ${{ needs.prepare.outputs.slug }}
```

`ghast` follows that chain across jobs and prints it back to you with a line number
at every hop.

---

## Quick start

```bash
git clone https://github.com/citizen204/ghast && cd ghast
make demo          # see it find things, and correctly not find things
pip install -e .   # optional: puts `ghast` on your PATH
```

No configuration, one dependency (PyYAML), Python 3.9+. Every `make` target runs
from the source tree, so nothing needs installing first.

```bash
ghast scan .                      # the current repository
ghast scan path/to/workflow.yml   # one file
ghast scan . --explain            # show the reasoning behind every score
ghast scan . --format sarif -o ghast.sarif   # upload to GitHub code scanning
ghast hunt owner/repo --top 50    # scan other people's repositories, read-only
ghast explain GHAST003            # the full write-up for one rule
```

Exit code is `0` when clean, `1` when something at or above `--fail-on`
(default: `high`) remains, `2` on a usage error.

---

## What it looks like

```
.github/workflows/triage.yml
────────────────────────────

[CRITICAL] GHAST003:27  github.event.issue.body reaches `$GITHUB_ENV`
      job `notify` · step `run: echo "SUMMARY=${BODY:0:80}" >> $GITHUB_ENV` · score 10.0
      Attacker-controlled value is appended to $GITHUB_ENV or $GITHUB_PATH. $GITHUB_ENV
      is parsed line by line, so a newline in the value sets arbitrary variables for
      every later step.

         27 │ - run: echo "SUMMARY=${BODY:0:80}" >> $GITHUB_ENV

      data flow:
        ● github.event.issue.body (line 23)
        ↓ job env BODY (line 23)
        ↓ written through $BODY (line 27)
        ↓ written to $GITHUB_ENV (line 27)

      why this score:
        - reachable via `issues` (any user can open an issue)
        - no permissions: block, so GITHUB_TOKEN keeps the repository default
        impact 10.0 x attacker any-github-user (x1.00) = 10.0

      fix:
        Use the delimited form with a delimiter the attacker cannot guess ...
```

---

## The idea it is built on

Three questions decide whether a workflow finding matters. `ghast` answers all three
before it assigns a severity, and shows its working under `--explain`.

**1. Can an outsider actually supply this value?**

`github.event.issue.title` is attacker-controlled. `github.event.issue.number` is an
integer GitHub generates. `github.actor` is a login from a constrained charset.
[`knowledge.py`](ghast/knowledge.py) catalogues which payload paths an outsider chooses,
and who has to be the attacker: anyone with a GitHub account, or someone with push
access. A path that is not in the catalogue is not a source.

It also records which *events* populate which paths. A workflow that runs only
`on: push` and mentions `github.event.issue.title` is referencing a value that does not
exist there, and is not reported.

**2. Does the value reach something that interprets it?**

Direct `${{ }}` interpolation into `run:` is always execution — the expansion happens
before any shell parses the script, so quoting in the YAML cannot contain it.

Going through the environment is the documented fix, and `ghast` will not flag it:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"        # correct — reported as nothing
```

But the fix only holds if the value is never handed back to a parser, so
[`shell.py`](ghast/shell.py) tracks quoting state, comments, and command position:

| script | verdict |
|---|---|
| `echo "$TITLE"` | safe |
| `echo $TITLE` | argument injection (low) |
| `eval "$TITLE"` | command execution (high) |
| `sudo $TITLE` | command execution (high) |
| `X=$(echo $TITLE)` | safe |
| `echo 'literal $TITLE'` | safe |
| `echo "K=$TITLE" >> $GITHUB_ENV` | environment-file injection (critical) |

That last row is the one most tools miss. `$GITHUB_ENV` is parsed line by line after
the step ends, so a newline in the value is a free variable assignment for every later
step — and `NODE_OPTIONS`, `LD_PRELOAD` or `BASH_ENV` turn that into code execution
without any `run:` block being involved.

**3. What does the attacker get?**

A fork `pull_request` gives a read-only token and no secrets; `pull_request_target` and
`issue_comment` give both. A `permissions:` block that pins the token to `contents: read`
changes the answer again, and so does an `if:` condition that checks the actor's
association with the repository. The score is the product:

```
impact × attacker-privilege × guard-strength × confidence
```

Every factor is printed. If you disagree with a finding, you can see exactly which
assumption to argue with.

---

## Rules

| Rule | What it finds |
|---|---|
| `GHAST001` | Attacker-controlled value substituted into a shell script |
| `GHAST002` | Attacker-controlled value reaching an action input executed as code |
| `GHAST003` | Attacker-controlled value appended to `$GITHUB_ENV` / `$GITHUB_PATH` |
| `GHAST004` | A variable holding attacker data re-parsed as a command |
| `GHAST005` | Unquoted expansion allowing argument injection |
| `GHAST006` | The `uses:` reference itself is attacker-controlled |
| `GHAST007` | Attacker-controlled value passed to a third-party action |
| `GHAST010` | Pwn request: a privileged workflow checks out untrusted PR code |
| `GHAST011` | Build tooling runs over untrusted code in a privileged job |
| `GHAST012` | `GITHUB_TOKEN` broader than the job needs |
| `GHAST013` | Secrets in a job that executes pull request code |
| `GHAST014` | A privileged job gated only on the actor being a bot |
| `GHAST015` | `toJSON(secrets)` serialises every secret into one step |
| `GHAST020` | Third-party action referenced by a mutable tag |
| `GHAST021` | Third-party action referenced by a branch |
| `GHAST022` | Privileged `workflow_run` job consuming untrusted artifacts |
| `GHAST023` | Fork-triggered job populating a shared Actions cache |
| `GHAST024` | Container image referenced by a mutable tag |
| `GHAST030` | Self-hosted runner reachable by outsiders |
| `GHAST031` | checkout leaves a git token in the workspace while untrusted code runs |
| `GHAST032` | A validation step that cannot fail the workflow |

`ghast explain <rule>` prints the full description and remediation for any of them.

---

## Validation

Run against **709 workflow files** in 29 major open-source repositories
(Kubernetes, PyTorch, VS Code, Next.js, React, Django, Rust, Home Assistant,
ClickHouse, Kibana, Grafana, Supabase and others):

| | |
|---|---|
| Files scanned | 709 |
| Distinct critical/high issues | 8, across 5 repositories |
| False positives among them | 0 — each was read by hand against the source |

Every finding at critical or high was manually traced back to the workflow file before
this number was written down. The hardened examples in
[`examples/safe/`](examples/safe/) produce **zero** findings, which matters more than
the true-positive count: a scanner that flags the documented fix is one nobody runs
twice.

Thirteen rules exist in their current form *because* of that exercise, the last of
them reported by a reader. Each case is pinned
as a regression test in [`tests/test_rules.py`](tests/test_rules.py), named after the
repository that found it, and the whole exercise is written up in
[**I built a GitHub Actions security scanner, then spent longer proving it
wrong**](docs/WRONG-TWELVE-TIMES.md) — including the one where the tool was not merely
imprecise but factually wrong about how GitHub works:

- **`npm install -g <pinned-package>` is not repo code.** A substring match on
  `"npm install"` called a generated Kibana workflow a critical. Whether a command
  hands control to the checked-out tree depends on its arguments, so
  `detect_repo_code_execution` parses them.
- **`blacksmith-*`, `depot-*`, `warp-*` runners are ephemeral.** Treating them as
  self-hosted produced 20+ false criticals on Supabase alone. The persistence argument
  behind the self-hosted rule does not apply to a VM that is destroyed after the job.
- **Artifact paths must match by segment, not substring.** The artifact
  `preview-tarballs` made `scripts/upload-preview-tarballs.js` — a file from the
  checkout — look attacker-controlled, and reported a well-hardened Next.js workflow
  as high severity.
- **Repeats are folded.** ClickHouse has one self-hosted runner decision, expressed
  across 212 generated jobs. Printing it 212 times buries everything else, so
  human-facing output collapses it to one entry that names the other jobs. JSON and
  SARIF keep every occurrence, because those consumers want a location per annotation.
- **Delegated permission gates are recognised.** The
  `needs.check-permissions.outputs.is_authorized == 'true'` pattern is a real control,
  and `ghast` checks that the gate job actually inspects the actor before crediting it.
- **Quoting decides whether command position is possible.**
  `ENTRY="- ${PR_TITLE} ..."` is a string assignment, not an invocation. The
  assignment-prefix match saw `ENTRY="-` plus a space and called a correctly hardened
  workflow a high-severity execution sink.
- **Guards propagate down the `needs:` graph.** huggingface/transformers gates one job
  on `author_association` and lets six later jobs inherit it — GitHub skips a job whose
  dependency was skipped, so those jobs do not repeat the condition. Reading only each
  job's own `if:` reported a carefully hardened workflow as a critical pwn request.
  `ghast` walks the dependency graph, and stops inheriting when a job opts out of the
  skip with `always()` or `!cancelled()`.
- **The cache-poisoning rule was making a false claim.** It fired on any `actions/cache`
  step in a `pull_request` workflow, asserting that fork CI can seed a cache the default
  branch later restores. GitHub scopes a pull request's caches to `refs/pull/N/merge`,
  which nothing else restores, and gives low-trust triggers read-only access to the
  default branch's scope — so that cannot happen. The rule produced 60 of 61 medium
  findings in one long-tail sweep, every one of them wrong, and is now narrowed to the
  shape that is real: a job on a cache-writing trigger (`push`, `workflow_run`,
  `schedule`) that caches something *after* checking out a pull request head or unpacking
  an untrusted artifact.
- **Cache-write permission is an event allow-list, not a privilege level.** A reader of
  the write-up pointed out that `pull_request_target` has the default branch as its
  `GITHUB_REF`, and asked whether it therefore belonged in the replacement rule's
  write-scope list. The premise is right; the conclusion is not — GitHub gates cache
  writes on an explicit list of events and names `pull_request_target`, `issue_comment`
  and `workflow_run` as read-only against the default branch's scope. Checking it found
  `workflow_run` sitting in that list in `ghast`, where it never belonged, put there by
  the same wrong assumption: that holding secrets and a write token implies being able
  to write the cache.
- **An actor check is not always spelled `github.actor`.** Stirling-Tools/Stirling-PDF
  allow-lists eight maintainer logins through `github.event.comment.user.login`, which is
  the field an `issue_comment` workflow actually cares about. Matching only `github.actor`
  reported a 92k-star repository as an unguarded critical pwn request.
- **An approval covers a commit, not a pull request.** When a human opt-in (a comment, a
  label) is followed by a checkout of `refs/pull/N/merge`, the ref re-resolves — so the
  approval ends up covering whoever pushed last. `ghast` says so, unless the workflow
  compares the merge commit's timestamp against the trigger, which
  huggingface/transformers does in a separate job reached through `needs:`.
- **A custom runner label is genuinely ambiguous.** Organisations name their
  GitHub-hosted larger runners whatever they like — `vscode-large-runners`,
  `gemini-cli-ubuntu-16-core` — and a self-hosted runner is also just a string. Nothing
  in the workflow file separates them, so `ghast` reports these as *unresolved* at
  reduced confidence and says so, while a literal `self-hosted` label stays certain.
- **`path: ./tmp` is isolation.** Treating every relative download path as unsafe
  misreported ant-design/ant-design; only an unset path drops the artifact on top of the
  checkout.
- **A gate need not use a comparison.** `if: fromJSON(needs.check-trust.outputs.trusted)`
  is an authorisation gate that an operator-anchored pattern misses. `ghast` now finds
  it — and then reports that `check-trust` never actually inspects the actor, which is
  the real problem with that particular gate.
- **Not every third-party runner is ephemeral.** Blacksmith and Depot destroy the VM
  after each job; CodSpeed's macro runners are dedicated bare metal whose purpose is
  hardware consistency, which is a different claim. `ghast` keeps three classes and, for
  the middle one, reports the finding while saying plainly that whether state survives is
  the provider's business and is not visible in the workflow file.
- **`workflow_run` reachability is a property of the *other* workflow.** A deployment
  pipeline that interpolates `workflow_run.head_branch` is a real injection shape, but if
  the workflow that triggers it only runs on `push`, the branch name comes from someone
  who already has write access. `ghast` resolves the upstream workflow by the name in
  `on.workflow_run.workflows` and scores accordingly — critical when the parent is
  fork-reachable, low when it is not, and worst-case when it cannot be resolved.

### The tool now reports the shape that caught its worst bug

GHAST023's false claim about cache scoping was not caught by a test. It was caught
by a ratio: **59 of 61** medium findings came from that one rule. Every test passed
before and after, because every test encoded the same wrong belief the code did.

So `ghast hunt` now prints the per-rule distribution whenever one rule holds most of
a severity band:

```
medium severity — 61 findings across 59 repositories
  GHAST023     59   97%  <-- dominates this band
  GHAST020      2    3%

One rule holding most of a severity band usually means the rule is describing
something normal, not something rare. Re-read what GHAST023 claims against the
platform's documentation before trusting these findings. This is a shape, not a
verdict — a widespread real mistake looks the same.
```

It is deliberately not a correctness check, and it says so. A rule may legitimately
dominate a band if the mistake it detects is genuinely common, and a wrong rule that
fires twice will never appear here at all. It reports a shape and names the rule to
go and re-read. `--distribution` prints it unconditionally.

---

## Use it in CI

```yaml
name: workflow-security
on:
  pull_request:
    paths: ['.github/workflows/**']
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  ghast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065  # v5.6.0
        with:
          python-version: '3.11'
      - run: pip install ghast
      - run: ghast scan . --format sarif -o ghast.sarif --fail-on never
      - uses: github/codeql-action/upload-sarif@main
        with:
          sarif_file: ghast.sarif
```

Findings land in the Security tab and as inline annotations on the pull request.
`partialFingerprints` are stable across line moves, so GitHub will not re-raise a
finding you have already triaged just because the file shifted.

---

## Prior art, and why this exists anyway

[**zizmor**](https://github.com/zizmorcore/zizmor) is the mature tool in this space and
you should probably run it: Rust, ~38 audits, maintained by a Trail of Bits engineer,
with a trophy case that includes CPython, cURL and Rust itself. It covers things `ghast`
does not — impostor-commit detection being the obvious one. If you only run one scanner,
run that one.

Others worth knowing: [**actionlint**](https://github.com/rhysd/actionlint) (fast
correctness linter, security is not its main job),
[**poutine**](https://github.com/boostsecurityio/poutine) (BoostSecurity, broad
supply-chain coverage across CI providers), and
[**octoscan**](https://github.com/synacktiv/octoscan) (Synacktiv, offensive-leaning,
strong on dangerous triggers and runner takeover).

A 2026 survey of nine of these scanners
([arXiv:2601.14455](https://arxiv.org/abs/2601.14455)) found that no single tool covers
all weakness classes, and recommends layering. `ghast` is built for one of those layers,
and it is deliberately narrow:

**What it does differently.**

- **Provenance, not just detection.** Taint is followed through workflow/job/step `env`,
  `$GITHUB_ENV` and `$GITHUB_OUTPUT` writes, step outputs, job outputs and matrix
  entries — and the resulting chain is *printed*, with a line number at every hop. A
  four-hop flow that crosses a job boundary is reported as a four-hop flow, not as a
  bare hit on the final line.
- **Severity you can argue with.** Every score is
  `impact × attacker-privilege × guard × confidence`, and `--explain` prints each factor
  and the arithmetic. When you think a finding is overrated you can point at the
  assumption rather than muting the rule.
- **Hunting, not just guarding.** `ghast hunt` scans other people's public repositories
  read-only and ranks the results, because finding this bug class at scale is a
  different job from keeping it out of one repository.

**What it does not do.** Fewer rules than zizmor. No impostor-commit detection. No
auto-fix. Reusable workflows are not followed across the `uses:` boundary. It is young
and has nothing like zizmor's field record. Version 0.1.0 means what it says.

## Design notes

```
ghast/
  yamlpos.py     YAML loader that keeps line/column for every key
  expr.py        ${{ }} parser: context references, normalised and offset-tagged
  model.py       Workflow / Job / Step, plus composite action.yml
  knowledge.py   the security model: sources, triggers, sinks, runner classes
  shell.py       quoting, command position, environment-file writes
  guards.py      recognising `if:` conditions used as authorisation
  taint.py       the propagation engine
  rules/         thin rules over the engine's output
  report/        terminal, JSON, SARIF, Markdown
  hunt.py        read-only batch scanning over GitHub repositories
```

The deliberate split: `knowledge.py` holds the *claims* about GitHub's execution model,
and every rule is a thin function over the engine's output. Disagreeing with `ghast`
should mean editing one table, not chasing logic through a dozen rules.

**Known limits.** Multi-line heredoc writes to `$GITHUB_ENV` are only partly modelled.
Outputs of third-party actions are treated as possibly-tainted when their inputs are,
which is conservative. Reusable workflows called with `uses:` at job level are not
followed into their definition. Composite actions are analysed, but without knowing
which workflow calls them, so their triggers are assumed worst-case.

---

## Development

```bash
make test     # 92 tests
make demo     # examples/vulnerable reports 9 criticals; examples/safe reports nothing
make scan     # ghast scanning its own workflows
make hunt     # read-only sweep of the 25 most-starred public repositories
```

`ghast` scans its own workflows in CI.

## License

MIT.
