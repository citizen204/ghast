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


def test_cache_poisoning_on_fork_pr():
    findings = analyse("""
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          key: deps-${{ hashFiles('**/lock') }}
          path: ~/.cache
""")
    assert "GHAST023" in rule_ids(findings)


def test_cache_restore_only_is_not_flagged():
    findings = analyse("""
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache/restore@v4
        with:
          key: deps
          path: ~/.cache
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
