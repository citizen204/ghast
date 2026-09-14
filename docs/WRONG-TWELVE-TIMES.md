# I built a GitHub Actions security scanner, then spent longer proving it wrong

The number that gave it away was 59 out of 61.

I had just finished a sweep of 67 mid-sized open-source repositories — the kind
with real CI but not enough fame to have been audited by anyone. My scanner
reported 61 medium-severity findings. Fifty-nine of them came from a single
rule.

No rule is that important. A rule that accounts for 97% of a severity band is
not detecting something rare; it is describing something normal and calling it
dangerous. So I stopped looking at the repositories and went to read GitHub's
documentation about the thing my rule claimed.

My rule was wrong. Not imprecise — wrong, about how the platform works, in the
text it printed to users.

This is a write-up of that, and of eleven other times the same tool told me
something false with complete confidence.

---

## The tool

`ghast` is a taint-analysis scanner for GitHub Actions workflows. It traces
attacker-controlled data — an issue title, a comment body, a fork's branch
name — from where it enters a workflow to wherever something interprets it, and
scores each finding by what an attacker actually gets.

The interesting bugs in CI are rarely visible one `run:` block at a time,
because the data travels:

```
github.event.comment.body
  → job env: TITLE
  → echo "slug=$TITLE" >> $GITHUB_OUTPUT     (step output)
  → needs.prepare.outputs.slug               (a different job)
  → run: ./deploy.sh ${{ needs.prepare.outputs.slug }}
```

Four hops, two jobs. Every individual line looks fine.

That part works. This article is not about that part.

---

## The method

The design constraint I set at the start was: **the documented mitigation must
never be flagged.** GitHub tells people to route untrusted values through the
environment and quote the read:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
```

A scanner that reports that line is a scanner nobody runs twice. Everything
below follows from taking that seriously.

So I built a batch mode — point it at a list of public repositories, read their
workflows over the API, rank what comes back — and ran it against roughly 200
repositories across five language corpora and one long-tail sweep: about 1,800
workflow files.

Then I read every high-severity finding by hand, against the actual source.

Total number of exploitable vulnerabilities found: **zero.**

Total number of bugs found in my own scanner: **twelve.**

They fall into four groups, and the groups get worse as they go.

---

## Group 1: the pattern was too loose

These are ordinary bugs. A regex matched more than I meant it to.

**`ENTRY="- ${PR_TITLE}"` is not a command.**

`rtk-ai/rtk` came back as a high-severity execution sink for this:

```bash
ENTRY="- ${PR_TITLE} [#${PR_NUMBER}](${PR_URL})"
```

That is the *correct* pattern. The value arrives through `env:` and every read
is quoted. My command-position detector saw `ENTRY="-` followed by a space,
matched it against "one or more `NAME=value` assignments", and concluded the
variable sat where the shell expects a command name.

It does not. The unterminated double quote means everything after it is one
word. Command position is only possible for an *unquoted* read — a distinction
the detector was not making at all, because it folded "is this in `eval`?" and
"is this in command position?" into a single boolean. `eval "$V"` is execution
regardless of quoting; `$V` in command position is execution only when bare.
Two different questions.

**`npm install -g <pinned-package>` does not run your repository's code.**

A generated workflow in `elastic/kibana` installs a pinned CLI after checking
out a pull request head. My rule for "does this job execute the checked-out
tree?" was a substring match against a list containing `"npm install"`.

Whether a package manager hands control to the working directory depends
entirely on its arguments. `npm ci` runs whatever lifecycle scripts the tree's
`package.json` declares. `npm install -g @scope/pkg@1.2.3` fetches a named
package from a registry and never reads the tree. Same six characters at the
front, opposite security properties.

**`preview-tarballs` is not `upload-preview-tarballs.js`.**

`vercel/next.js` has a well-hardened `workflow_run` pipeline: minimal
permissions, SHA-pinned actions, a sparse checkout of exactly one script, and
the artifact downloaded into `${{ runner.temp }}` rather than the workspace. I
reported it as high severity.

The artifact is named `preview-tarballs`. The script that reads it is
`scripts/upload-preview-tarballs.js`. I was deciding "does this path point into
the downloaded artifact?" with a substring check, so a file from the checkout
looked attacker-controlled. Paths compare by segment, never by substring.

**`path: ./tmp` is isolation.**

`ant-design/ant-design` downloads an untrusted artifact and unpacks it. I
reported that the download "unpacks into the workspace and can overwrite the
files the checkout placed there" — but their download step sets `path: ./tmp`.

I was testing whether the path was isolated by checking that it did not start
with `.`, which rejects every relative path. A named subdirectory keeps the
artifact off the checkout's own files; only an unset path, or the workspace root
itself, drops it on top of them.

---

## Group 2: the answer was in another file

These are more interesting, because the code was doing exactly what I wrote. I
had simply written something that could not be correct while looking at one
file, or one job, at a time.

**Whether `workflow_run` is reachable is a property of a different workflow.**

`ruvnet/RuView` — 93k stars — came back at 10.0, critical. A six-hop chain
across three jobs, ending in `kubectl set image` on a production deployment:

```
github.event.workflow_run.head_branch
  → step env PUBLISHED_REF
  → $GITHUB_OUTPUT → job output
  → needs.pre-deployment.outputs.image_tag
  → kubectl set image deployment/...
```

The data flow is real. The injection shape is real: a branch named `v$(...)`
passes their `== v*` check, and git permits `$`, `(` and `)` in refnames.

What was wrong was the attacker. I treated `workflow_run` as reachable by
anyone, unconditionally. It is not: its reachability is a property of the
workflow named in `on.workflow_run.workflows`. That workflow runs on push to
main, on `v*` tags, and on `workflow_dispatch`. All three need write access.
So the branch name can only come from someone who already has push access, and
"critical, any GitHub user" overstated it by an order of magnitude.

Fixing this meant making scanning two-pass — parse every workflow in the
repository before analysing any of them — so a rule can ask about a file other
than the one it is looking at.

**A guard on one job protects every job downstream of it.**

`huggingface/transformers` came back as a critical pwn request. It is close to
the opposite. Their comment-triggered CI gates `get-pr-number` on an
`author_association` allow-list, and there is a `check-timestamps` job whose
only purpose is to refuse to run when the merge commit is newer than the
comment that triggered it — a defence against the exact race where a maintainer
approves and the contributor then pushes.

The job doing the checkout carries no `if:` of its own, because it does not need
one. GitHub skips a job when anything in its `needs:` was skipped, so the gate
upstream holds the whole chain. I was reading each job's own condition and
nothing else.

**An actor check is not always spelled `github.actor`.**

`Stirling-Tools/Stirling-PDF` — 92k stars — came back as two criticals:
`issue_comment` checking out `refs/pull/N/merge` with secrets in scope, no
guard detected.

There is a guard. It allow-lists eight maintainer logins:

```yaml
github.event.comment.user.login == 'frooodle' ||
github.event.comment.user.login == 'sf298' || ...
```

For an `issue_comment` workflow, the comment author *is* the actor that
matters. I was matching `github.actor` and nothing else. The same applies to
`pull_request.user.login`, `sender.login`, and the review variants.

**A gate does not need a comparison operator.**

`ant-design/ant-design` gates a privileged job with:

```yaml
if: fromJSON(needs.check-trust.outputs.trusted)
```

My delegated-gate pattern required `== 'true'` after the output reference, so
it saw no gate at all.

Recognising it turned out to be worth more than the severity change, because it
let the tool report the more interesting fact: `check-trust` compares
`workflow_run.repository` against the repository name — and for a fork pull
request, `workflow_run.repository` is the *base* repository. The gate keeps the
workflow from running in forks. It says nothing whatsoever about who wrote the
artifact it is about to unpack. The tool now prints: *"gated on
`needs.check-trust.outputs.trusted`, but job `check-trust` was not seen checking
who the actor is."*

---

## Group 3: I asserted things I could not know

These are the ones I find most uncomfortable, because the code had no bug. It
was confidently answering a question the input does not contain.

**Not every non-GitHub runner is a persistent machine.**

My self-hosted-runner rule scores code execution at 9.0 even when no secrets are
present, because a self-hosted runner is a computer: whatever an attacker leaves
behind is waiting for the next, possibly privileged, job.

`supabase/supabase` produced twenty-odd criticals on runners named
`blacksmith-*`. Blacksmith is a managed provider whose VMs are destroyed after
every job. The persistence argument — the entire basis for that 9.0 — does not
apply. So I added a list of managed providers and stopped flagging them.

Then `langchain-ai/langchain` turned up `codspeed-macro`, and my new list
quietly got that wrong in the other direction. CodSpeed's macro runners are
*dedicated bare metal*, and hardware consistency is the whole product — which
argues against tearing them down between jobs. I read their documentation and
still could not tell whether state survives.

So the tool now has a third class, and says what it does not know: *"whether it
is torn down between jobs is the provider's business and is not visible here."*

**And a custom label is genuinely ambiguous.**

Then `microsoft/vscode` produced `vscode-large-runners` and `google-gemini/
gemini-cli` produced `gemini-cli-ubuntu-16-core`, and I had to admit the deeper
problem: organisations name GitHub-hosted larger runners whatever they like, and
a self-hosted runner is also just a string. **Nothing in the workflow file
distinguishes them.**

A literal `self-hosted` in the labels is unambiguous and still scores full
confidence. Everything else is now reported as *unresolved*, at reduced
confidence, with the ambiguity stated in the output.

I had been printing a conclusion the input could not support. Twice.

---

## Group 4: I was wrong about the platform

Which brings us back to 59 out of 61.

The rule was cache poisoning. It fired on any `actions/cache` step in a
`pull_request` workflow, and it told the reader:

> cache entries created here are visible to default-branch workflows through the
> cache fallback rules

That is false. From [GitHub's cache
documentation](https://docs.github.com/en/actions/reference/dependency-caching-reference):
a pull request's caches are scoped to `refs/pull/N/merge` and can only be
restored by re-runs of that pull request. Low-trust triggers get **read-only**
access to the default branch's scope. Cache sharing flows downward, from the
default branch to feature branches, and never upward.

A plain `actions/cache` step in fork CI cannot poison anything. It is the
ordinary, documented, correct thing to do, and my tool was pointing at
fifty-nine projects doing it and making a false claim about the platform to
justify the accusation.

There *is* a real cache-poisoning shape. It is the mirror image: a job running
under a trigger that **can** write the default branch's scope — `push`,
`workflow_run`, `schedule`, `workflow_dispatch` — which caches something *after*
checking out a pull request head or unpacking an artifact from an untrusted run.
Whatever it caches is derived from attacker-controlled input, and every later
run on the default branch restores it.

That is what the rule detects now. Across the same corpus, it fires almost
never — which is what a rule about a genuine, specific mistake should do.

---

## What this cost, and what it is worth

The scanner has 120 tests. They passed before this bug, during it, and after
it. Not one of them was capable of catching it, and no amount of additional
testing would have been, because every test encoded the same wrong belief the
code did.

**A test suite proves your code matches your model. It cannot tell you your
model is wrong.**

The thing that caught it was a number with the wrong shape. Fifty-nine out of
sixty-one. Not a failure, not an exception, not a diff — a distribution that
did not look like the world.

That is the actual finding here, and it generalises past CI security. Every
static analysis tool is a set of claims about how a platform behaves. The code
can be perfect and the claims can still be false, and users will not tell you,
because a tool that cries wolf does not get bug reports. It gets muted.

The tool is better now, and I trust it much less than I did a week ago. Those
turn out to be the same sentence.

All twelve cases are pinned as regression tests, each one named after the
repository that found it. The public corpus is the test suite.

---

*`ghast` is MIT-licensed and lives at
[github.com/citizen204/ghast](https://github.com/citizen204/ghast). It scans its
own workflows in CI. Everything above is reproducible with `ghast hunt`.*

*Every repository mentioned is public and was read through the GitHub API. No
finding was tested against anyone's CI, and nothing here is a vulnerability
report: every high-severity result discussed turned out to be either a
deliberate architectural choice or a bug in my own tool.*
