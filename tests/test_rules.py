from helpers import analyse, of_rule, rule_ids


def test_pwn_request_detected():
    findings = analyse("""
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
""")
    assert "GHAST010" in rule_ids(findings)
    assert "GHAST011" in rule_ids(findings)
    assert of_rule(findings, "GHAST010")[0].severity == "critical"


def test_pull_request_target_without_head_checkout_is_fine():
    findings = analyse("""
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
      - run: gh pr edit --add-label triage
""")
    assert "GHAST010" not in rule_ids(findings)
    assert "GHAST011" not in rule_ids(findings)


def test_author_association_guard_lowers_severity():
    guarded = analyse("""
on: pull_request_target
jobs:
  build:
    if: github.event.pull_request.author_association == 'COLLABORATOR'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    unguarded = analyse("""
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
    assert of_rule(guarded, "GHAST010")[0].score < of_rule(unguarded, "GHAST010")[0].score


def test_self_hosted_runner_on_fork_pr():
    findings = analyse("""
on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: make test
""")
    assert "GHAST030" in rule_ids(findings)


def test_self_hosted_runner_on_push_only_is_not_reported():
    findings = analyse("""
on: push
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: make test
""")
    assert "GHAST030" not in rule_ids(findings)


def test_sha_pinned_actions_are_not_flagged():
    findings = analyse("""
on: push
permissions:
  contents: read
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: third/party@1234567890abcdef1234567890abcdef12345678
""")
    assert "GHAST020" not in rule_ids(findings)
    assert "GHAST021" not in rule_ids(findings)


def test_branch_ref_is_worse_than_tag_ref():
    branch = analyse("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: third/party@main
""")
    tag = analyse("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: third/party@v1.2.3
""")
    assert of_rule(branch, "GHAST021")[0].score > of_rule(tag, "GHAST020")[0].score


def test_first_party_actions_score_lower():
    first = analyse("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    third = analyse("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: randomuser/checkout@v4
""")
    assert of_rule(first, "GHAST020")[0].score < of_rule(third, "GHAST020")[0].score


def test_narrow_permissions_are_not_flagged():
    findings = analyse("""
on: issues
permissions:
  contents: read
  issues: write
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
""")
    assert "GHAST012" not in rule_ids(findings)


def test_write_all_is_flagged_once_per_declaration():
    findings = analyse("""
on: push
permissions: write-all
jobs:
  a:
    runs-on: ubuntu-latest
    steps: [{run: echo a}]
  b:
    runs-on: ubuntu-latest
    steps: [{run: echo b}]
""")
    assert len(of_rule(findings, "GHAST012")) == 1


def test_tojson_secrets_flagged():
    findings = analyse("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}'
""")
    assert "GHAST015" in rule_ids(findings)


def test_artifact_poisoning_on_workflow_run():
    findings = analyse("""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: results
      - run: unzip results.zip && source ./results/env.sh
""")
    assert "GHAST022" in rule_ids(findings)


def test_ordinary_pr_caching_is_not_poisoning():
    """GitHub scopes a pull request's caches to `refs/pull/N/merge` and gives
    low-trust triggers read-only access to the default branch's scope, so a
    plain `actions/cache` step in fork CI cannot poison anything. Flagging it
    produced 60 of 61 medium findings in one long-tail sweep -- all wrong."""
    findings = analyse("""
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@1234567890abcdef1234567890abcdef12345678
        with:
          key: deps-${{ hashFiles('**/lock') }}
          path: ~/.cache
""")
    assert "GHAST023" not in rule_ids(findings)


def test_cache_written_after_untrusted_checkout_on_a_trusted_trigger():
    """The shape that is actually dangerous: a trigger that *can* write the
    default branch's cache scope, in a job that first checked out a PR head."""
    findings = analyse("""
on:
  workflow_dispatch:
    inputs:
      pr_number:
        required: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: refs/pull/${{ github.event.inputs.pr_number }}/merge
      - uses: actions/cache@1234567890abcdef1234567890abcdef12345678
        with:
          key: build-${{ github.sha }}
          path: target/
""")
    finding = of_rule(findings, "GHAST023")[0]
    assert any("may write the default branch's cache scope" in n
               for n in finding.factors.notes)
    assert any("checked out" in n for n in finding.factors.notes)


# --- which events may write the default branch's cache scope ---------------
#
# Reported by a reader of the write-up, who pointed out that
# `pull_request_target` has the default branch as its GITHUB_REF and therefore
# looked like it belonged in the write list. The premise is right and the
# conclusion is wrong -- GitHub gates cache writes on an event allow-list, not
# on the ref or on what the run can reach. Checking it found `workflow_run`
# sitting in the list, where it never belonged.

def _cache_after_untrusted(trigger_block, ref_expr):
    return analyse("""
on:
""" + trigger_block + """
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: """ + ref_expr + """
      - uses: actions/cache@1234567890abcdef1234567890abcdef12345678
        with:
          key: build-x
          path: target/
""")


def test_workflow_run_cannot_write_the_default_branch_cache_scope():
    """GitHub names workflow_run as low-trust with read-only access to the
    default branch's cache scope, despite it holding secrets and a write
    token. Privilege and cache-write permission are separate things."""
    findings = _cache_after_untrusted(
        "  workflow_run:\n    workflows: [CI]\n    types: [completed]",
        "${{ github.event.workflow_run.head_sha }}")
    assert "GHAST023" not in rule_ids(findings)


def test_pull_request_target_cannot_write_the_default_branch_cache_scope():
    """Its GITHUB_REF *is* the default branch and it *does* check out fork code
    with secrets -- and it still cannot write the cache."""
    findings = _cache_after_untrusted(
        "  pull_request_target:",
        "${{ github.event.pull_request.head.sha }}")
    assert "GHAST023" not in rule_ids(findings)


def test_push_can_write_the_default_branch_cache_scope():
    findings = _cache_after_untrusted(
        "  push:\n    branches: [main]",
        "refs/pull/${{ github.event.inputs.pr }}/merge")
    assert "GHAST023" in rule_ids(findings)


def test_cache_written_before_the_untrusted_checkout_is_clean():
    findings = analyse("""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@1234567890abcdef1234567890abcdef12345678
        with:
          key: deps
          path: ~/.cache
      - run: make build
""")
    assert "GHAST023" not in rule_ids(findings)


def test_bot_actor_trust():
    findings = analyse("""
on: pull_request_target
jobs:
  a:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.NPM_TOKEN }}
""")
    assert "GHAST014" in rule_ids(findings)


def test_persist_credentials_false_is_respected():
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          persist-credentials: false
      - run: npm ci
""")
    assert "GHAST031" not in rule_ids(findings)


def test_hardened_workflow_is_clean():
    findings = analyse("""
on:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: |
          echo "Triaging: $TITLE"
          ./scripts/label.sh "$TITLE"
""")
    assert findings == [], [f.rule_id + ": " + f.title for f in findings]


# --- regressions found by running against real repositories -----------------

def test_globally_installed_package_is_not_repo_code():
    """`npm install -g <pinned package>` never reads the checked-out tree.

    Found against elastic/kibana, where a generated workflow installs a pinned
    CLI after checkout and the coarse substring match called it a critical.
    """
    findings = analyse("""
on: pull_request_target
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/head
      - run: npm install -g @anthropic-ai/claude-code@2.1.165
""")
    assert "GHAST010" in rule_ids(findings)      # the checkout is still real
    assert "GHAST011" not in rule_ids(findings)  # but nothing ran the tree


def test_lockfile_driven_install_is_repo_code():
    findings = analyse("""
on: pull_request_target
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/head
      - run: npm ci
""")
    assert "GHAST011" in rule_ids(findings)


def test_delegated_permission_gate_lowers_severity():
    """The `check-permissions` job pattern, as used by elastic/kibana."""
    gated = analyse("""
on: pull_request_target
jobs:
  check-permissions:
    runs-on: ubuntu-latest
    outputs:
      is_authorized: ${{ steps.c.outputs.ok }}
    steps:
      - id: c
        uses: actions/github-script@1234567890abcdef1234567890abcdef12345678
        with:
          script: |
            const p = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo, username: context.actor})
            core.setOutput('ok', p.data.permission === 'write')
  build:
    needs: check-permissions
    if: needs.check-permissions.outputs.is_authorized == 'true'
    runs-on: self-hosted
    steps:
      - run: make test
""")
    finding = of_rule(gated, "GHAST030")[0]
    assert finding.factors.guard == "strong"
    assert finding.severity in ("low", "info")
    assert any("delegated" in note for note in finding.factors.notes)


def test_gate_job_that_checks_nothing_is_only_a_weak_guard():
    findings = analyse("""
on: pull_request_target
jobs:
  setup:
    runs-on: ubuntu-latest
    outputs:
      allowed: ${{ steps.c.outputs.v }}
    steps:
      - id: c
        run: echo "v=true" >> $GITHUB_OUTPUT
  build:
    needs: setup
    if: needs.setup.outputs.allowed == 'true'
    runs-on: self-hosted
    steps:
      - run: make test
""")
    assert of_rule(findings, "GHAST030")[0].factors.guard == "weak"


def test_artifact_download_consumed_by_trusted_script_is_not_critical():
    """facebook/react: a repo-owned script reads the artifact.

    Still worth reporting -- the download lands in the workspace -- but it is
    not the same as `source`ing attacker bytes.
    """
    findings = analyse("""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: results
      - run: node ./scripts/render-comment.js
""")
    finding = of_rule(findings, "GHAST022")[0]
    assert finding.severity != "critical"
    assert finding.factors.confidence == "likely"


def test_artifact_download_that_is_sourced_is_critical():
    findings = analyse("""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: results
      - run: source ./results/env.sh
""")
    finding = of_rule(findings, "GHAST022")[0]
    assert finding.severity == "critical"
    assert finding.factors.confidence == "certain"


def test_isolated_download_path_scores_lower():
    def build(path_line):
        return analyse("""
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: results
""" + path_line + """
      - run: unzip results.zip
""")
    isolated = of_rule(build("          path: /tmp/untrusted"), "GHAST022")[0]
    workspace = of_rule(build(""), "GHAST022")[0]
    assert isolated.score < workspace.score


def test_artifact_name_is_matched_by_path_segment_not_substring():
    """vercel/next.js: the artifact is `preview-tarballs`, and the script that
    reads it is `scripts/upload-preview-tarballs.js` -- a file from the
    checkout. A substring match called that a high-severity execution sink."""
    findings = analyse("""
on:
  workflow_run:
    workflows: [build]
    types: [completed]
permissions:
  contents: read
  id-token: write
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: preview-tarballs
          path: ${{ runner.temp }}/preview-tarballs
      - run: node scripts/upload-preview-tarballs.js "${{ runner.temp }}/preview-tarballs"
""")
    finding = of_rule(findings, "GHAST022")[0]
    assert finding.severity == "medium", finding.factors.explain()
    assert any("isolated" in note for note in finding.factors.notes)


def test_path_into_the_artifact_still_counts_as_execution():
    findings = analyse("""
on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: results
      - run: node results/index.js
""")
    assert of_rule(findings, "GHAST022")[0].severity == "critical"


def test_repeated_findings_collapse_for_humans():
    from ghast.scan import collapse
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: [self-hosted, big]
    steps: [{run: echo a}]
  b:
    runs-on: [self-hosted, big]
    steps: [{run: echo b}]
  c:
    runs-on: [self-hosted, big]
    steps: [{run: echo c}]
""")
    raw = of_rule(findings, "GHAST030")
    assert len(raw) == 3
    folded = of_rule(collapse(findings), "GHAST030")
    assert len(folded) == 1
    assert folded[0].occurrences == 3
    assert sorted(folded[0].other_jobs) == ["b", "c"]


def test_managed_ephemeral_runners_are_not_self_hosted():
    """supabase/supabase runs on Blacksmith, whose VMs are destroyed per job."""
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: blacksmith-2vcpu-ubuntu-2404
    steps: [{run: echo a}]
""")
    assert "GHAST030" not in rule_ids(findings)


def test_unknown_runner_label_is_still_self_hosted():
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: kibana
    steps: [{run: echo a}]
""")
    assert "GHAST030" in rule_ids(findings)


def test_sarif_upload_permission_is_not_reported():
    """`security-events: write` is required by the pattern this project
    recommends in its own README; flagging it would be self-defeating."""
    findings = analyse("""
on: push
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: echo scan
""")
    assert "GHAST012" not in rule_ids(findings)


def test_env_routed_value_in_a_quoted_assignment_is_clean():
    """The full rtk-ai/rtk shape: env indirection plus quoted reads."""
    findings = analyse("""
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Update Next Release PR
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_URL: ${{ github.event.pull_request.html_url }}
        run: |
          set -euo pipefail
          ENTRY="- ${PR_TITLE} [#${PR_NUMBER}](${PR_URL})"
          echo "$ENTRY"
""")
    injection = [f for f in findings if f.rule_id.startswith("GHAST00")]
    assert injection == [], [f.rule_id + " @" + str(f.line) for f in injection]


# --- workflow_run reachability depends on the workflow that triggers it -----

_UPSTREAM_PUSH_ONLY = """
name: Build and publish
on:
  push:
    branches: [main]
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: make build}]
"""

_UPSTREAM_FORK_PR = """
name: Build and publish
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: make build}]
"""

_DOWNSTREAM = """
name: Continuous Deployment
on:
  workflow_run:
    workflows: ["Build and publish"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - id: tag
        env:
          PUBLISHED_REF: ${{ github.event.workflow_run.head_branch }}
        run: echo "tag=$PUBLISHED_REF" >> $GITHUB_OUTPUT
      - run: docker manifest inspect "img:${{ steps.tag.outputs.tag }}"
"""


def _scan_pair(upstream, downstream, tmp_path):
    from ghast.scan import scan_paths

    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "upstream.yml").write_text(upstream)
    (directory / "cd.yml").write_text(downstream)
    result = scan_paths([str(tmp_path)], relative_to=str(tmp_path))
    return [f for f in result.findings if f.rule_id == "GHAST001"]


def test_workflow_run_behind_a_push_only_workflow_is_not_outsider_reachable(tmp_path):
    """ruvnet/RuView: the deployment pipeline interpolates
    `workflow_run.head_branch` into a shell command, which is a real injection
    shape -- but the workflow that triggers it only runs on push and
    workflow_dispatch, so the branch name comes from someone who already has
    write access. Scoring that as critical overstates it by an order of
    magnitude."""
    findings = _scan_pair(_UPSTREAM_PUSH_ONLY, _DOWNSTREAM, tmp_path)
    assert findings, "the injection itself must still be reported"
    finding = findings[0]
    assert finding.factors.actor == "write-access"
    assert finding.severity in ("low", "medium")
    assert any("only someone with write access" in n for n in finding.factors.notes)


def test_workflow_run_behind_a_fork_pr_workflow_stays_critical(tmp_path):
    findings = _scan_pair(_UPSTREAM_FORK_PR, _DOWNSTREAM, tmp_path)
    assert findings
    finding = findings[0]
    assert finding.factors.actor == "any-github-user"
    assert finding.severity == "critical"


def test_unresolvable_upstream_keeps_the_worst_case(tmp_path):
    """A single file scanned on its own has no siblings to consult, so the
    conservative reading has to survive."""
    from ghast.scan import scan_paths

    directory = tmp_path / ".github" / "workflows"
    directory.mkdir(parents=True)
    (directory / "cd.yml").write_text(_DOWNSTREAM)
    result = scan_paths([str(tmp_path)], relative_to=str(tmp_path))
    findings = [f for f in result.findings if f.rule_id == "GHAST001"]
    assert findings
    assert findings[0].factors.actor == "any-github-user"


# --- guards propagate down the needs graph ---------------------------------

def _comment_ci(gate_if, downstream_if=""):
    extra = "    if: {}\n".format(downstream_if) if downstream_if else ""
    return """
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  get-pr-number:
    if: %s
    runs-on: ubuntu-latest
    outputs:
      PR_NUMBER: ${{ steps.n.outputs.num }}
    steps:
      - id: n
        run: echo "num=1" >> $GITHUB_OUTPUT
  get-tests:
    needs: [get-pr-number]
%s    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: "refs/pull/${{ needs.get-pr-number.outputs.PR_NUMBER }}/merge"
          persist-credentials: false
""" % (gate_if, extra)


_ASSOC_GATE = ("${{ contains(fromJSON('[\"MEMBER\", \"OWNER\", \"COLLABORATOR\"]'), "
               "github.event.comment.author_association) }}")


def test_guard_on_an_upstream_job_protects_downstream_jobs():
    """huggingface/transformers gates `get-pr-number` on author_association and
    lets later jobs inherit it through `needs:`. GitHub skips a job whose
    dependency was skipped, so those jobs do not repeat the condition."""
    findings = analyse(_comment_ci(_ASSOC_GATE))
    finding = of_rule(findings, "GHAST010")[0]
    assert finding.factors.guard == "strong"
    assert finding.severity in ("low", "info")
    assert any("inherited through" in n for n in finding.factors.notes)


def test_always_breaks_the_inheritance():
    """`if: always()` runs the job even when its dependency was skipped, so the
    upstream guard no longer holds it back."""
    findings = analyse(_comment_ci(_ASSOC_GATE, downstream_if="${{ always() }}"))
    finding = of_rule(findings, "GHAST010")[0]
    assert finding.factors.guard is None
    assert finding.severity == "critical"


def test_ungated_upstream_inherits_nothing():
    findings = analyse(_comment_ci("${{ github.event.issue.state == 'open' }}"))
    finding = of_rule(findings, "GHAST010")[0]
    assert finding.factors.guard is None
    assert finding.severity == "critical"


def test_inheritance_survives_a_cycle_in_needs():
    """Malformed `needs:` must not hang the analysis."""
    findings = analyse("""
on: issue_comment
jobs:
  a:
    needs: [b]
    runs-on: ubuntu-latest
    steps: [{run: echo a}]
  b:
    needs: [a]
    runs-on: ubuntu-latest
    steps: [{run: echo b}]
""")
    assert isinstance(findings, list)


def test_third_party_managed_runner_is_reported_but_not_as_persistence():
    """langchain-ai/langchain runs benchmarks on `codspeed-macro`. CodSpeed's
    macro runners are dedicated bare metal for measurement consistency, which
    is not the same claim as Blacksmith's per-job VMs -- so ghast reports it
    and says what it cannot see, rather than guessing either way."""
    findings = analyse("""
on: pull_request
jobs:
  bench:
    runs-on: codspeed-macro
    steps: [{run: pytest --codspeed}]
""")
    finding = of_rule(findings, "GHAST030")[0]
    assert finding.severity != "critical"
    assert finding.factors.confidence == "likely"
    assert "Third-party managed" in finding.title
    assert any("provider's business" in n for n in finding.factors.notes)


def test_ephemeral_managed_runner_is_still_silent():
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: depot-ubuntu-24.04
    steps: [{run: echo a}]
""")
    assert "GHAST030" not in rule_ids(findings)


def test_explicit_self_hosted_label_stays_certain():
    """microsoft/vscode writes `self-hosted` literally. No ambiguity there."""
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: [self-hosted, "1ES.Pool=vscode-oss-ubuntu"]
    steps: [{run: echo a}]
""")
    finding = of_rule(findings, "GHAST030")[0]
    assert finding.factors.confidence == "certain"
    assert finding.severity == "critical"
    assert finding.title.startswith("Self-hosted")


def test_unresolvable_runner_label_is_reported_with_lower_confidence():
    """`vscode-large-runners` and `gemini-cli-ubuntu-16-core` could be an
    organisation's GitHub-hosted larger runners. Nothing in the workflow file
    distinguishes those from a self-hosted machine, so asserting one is wrong."""
    findings = analyse("""
on: pull_request
jobs:
  a:
    runs-on: gemini-cli-ubuntu-16-core
    steps: [{run: echo a}]
""")
    finding = of_rule(findings, "GHAST030")[0]
    assert finding.factors.confidence == "likely"
    assert "Non-GitHub-hosted" in finding.title
    assert any("does not say which" in n for n in finding.factors.notes)


def test_artifact_download_into_a_subdirectory_counts_as_isolated():
    """ant-design/ant-design uses `path: ./tmp`. That keeps the artifact off
    the checkout's own files; only an unset path drops it on top of them."""
    def build(path_line):
        return analyse("""
on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: report
""" + path_line + """
      - run: tar -xzvf tmp/report.tar.gz -C ./out
""")
    isolated = of_rule(build("          path: ./tmp"), "GHAST022")[0]
    workspace = of_rule(build(""), "GHAST022")[0]
    assert isolated.score < workspace.score
    assert any("isolated in `./tmp`" in n for n in isolated.factors.notes)


def test_boolean_delegated_gate_is_recognised_without_a_comparison():
    """`if: fromJSON(needs.check-trust.outputs.trusted)` is a gate. An
    operator-anchored pattern misses it, as it did on ant-design/ant-design."""
    findings = analyse("""
on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  check-trust:
    runs-on: ubuntu-latest
    outputs:
      trusted: ${{ steps.c.outputs.t }}
    steps:
      - id: c
        run: echo "t=true" >> $GITHUB_OUTPUT
  report:
    needs: [check-trust]
    if: fromJSON(needs.check-trust.outputs.trusted)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@1234567890abcdef1234567890abcdef12345678
        with:
          name: report
          path: ./tmp
      - run: tar -xzvf tmp/report.tar.gz -C ./out
""")
    finding = of_rule(findings, "GHAST022")[0]
    assert finding.factors.guard == "weak"
    assert any("not seen checking who the actor is" in n for n in finding.factors.notes)


# --- an approval covers a commit, not a pull request -----------------------

def _comment_deploy(gate, extra_job=""):
    return """
on:
  issue_comment:
    types: [created]
jobs:
  check-comment:
    if: %s
    runs-on: ubuntu-latest
    outputs:
      pr_number: ${{ steps.n.outputs.n }}
    steps:
      - id: n
        run: echo "n=1" >> $GITHUB_OUTPUT
%s  deploy:
    needs: [check-comment]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1234567890abcdef1234567890abcdef12345678
        with:
          ref: "refs/pull/${{ needs.check-comment.outputs.pr_number }}/merge"
      - run: echo "${{ secrets.DEPLOY_KEY }}" > /dev/null
""" % (gate, extra_job)


_LOGIN_ALLOWLIST = ("${{ github.event.comment.user.login == 'frooodle' || "
                    "github.event.comment.user.login == 'Ludy87' }}")


def test_comment_author_allowlist_is_a_strong_guard():
    """Stirling-Tools/Stirling-PDF allow-lists eight maintainer logins via
    `github.event.comment.user.login`. Matching only `github.actor` reported a
    92k-star repository as an unguarded critical."""
    findings = analyse(_comment_deploy(_LOGIN_ALLOWLIST))
    finding = of_rule(findings, "GHAST010")[0]
    assert finding.factors.guard == "strong"
    assert finding.severity in ("low", "info")


def test_mutable_ref_after_human_approval_is_called_out():
    findings = analyse(_comment_deploy(_LOGIN_ALLOWLIST))
    finding = of_rule(findings, "GHAST010")[0]
    assert any("re-resolves" in n for n in finding.factors.notes)


def test_a_freshness_check_in_a_needed_job_clears_the_race_note():
    """huggingface/transformers rejects merge commits newer than the comment
    that triggered the run, in a separate job reached through `needs:`."""
    guard_job = """  check-timestamps:
    needs: [check-comment]
    runs-on: ubuntu-latest
    steps:
      - name: Verify merge_commit timestamp is older than the comment
        run: |
          COMMENT_TIMESTAMP=$(date -d "$COMMENT_DATE" +"%s")
          if [ $COMMENT_TIMESTAMP -le $PR_MERGE_COMMIT_TIMESTAMP ]; then exit 1; fi
"""
    text = _comment_deploy(_LOGIN_ALLOWLIST, guard_job).replace(
        "needs: [check-comment]\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout",
        "needs: [check-comment, check-timestamps]\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout")
    findings = analyse(text)
    finding = of_rule(findings, "GHAST010")[0]
    assert not any("re-resolves" in n for n in finding.factors.notes)
