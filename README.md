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
git clone https://github.com/USERNAME/ghast && cd ghast
pip install -e .
ghast scan .
```

No configuration, one dependency (PyYAML), Python 3.9+.

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

Several rules exist in their current form *because* of that exercise, and the cases are
pinned as regression tests in [`tests/test_rules.py`](tests/test_rules.py):

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
pip install -e '.[dev]'
pytest              # 89 tests
ghast scan examples/vulnerable   # should report 10 criticals
ghast scan examples/safe         # should report nothing
```

`ghast` scans its own workflows in CI.

## License

MIT.
