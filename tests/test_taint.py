from ghast import model, taint
from helpers import analyse, of_rule, rule_ids


def sinks(text):
    workflow = model.parse_text(text, "t.yml")
    return taint.analyse(workflow).sinks


def test_direct_interpolation_is_a_sink():
    hits = sinks("""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
""")
    assert [h.kind for h in hits] == [taint.SINK_RUN_INTERPOLATION]


def test_env_indirection_with_quoting_is_not_a_sink():
    assert sinks("""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: echo "$T"
""") == []


def test_env_indirection_into_eval_is_a_sink():
    hits = sinks("""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: eval "$T"
""")
    assert [h.kind for h in hits] == [taint.SINK_RUN_ENV_EXEC]


def test_github_env_write_is_a_sink():
    hits = sinks("""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          T: ${{ github.event.issue.title }}
        run: echo "SUM=$T" >> $GITHUB_ENV
""")
    assert taint.SINK_ENV_FILE in {h.kind for h in hits}


def test_taint_crosses_jobs_through_outputs():
    hits = sinks("""
on: issue_comment
jobs:
  prep:
    runs-on: ubuntu-latest
    outputs:
      v: ${{ steps.s.outputs.v }}
    env:
      B: ${{ github.event.comment.body }}
    steps:
      - id: s
        run: echo "v=$B" >> $GITHUB_OUTPUT
  use:
    needs: prep
    runs-on: ubuntu-latest
    steps:
      - run: deploy ${{ needs.prep.outputs.v }}
""")
    kinds = [h.kind for h in hits]
    assert taint.SINK_RUN_INTERPOLATION in kinds
    cross = [h for h in hits if h.kind == taint.SINK_RUN_INTERPOLATION][0]
    assert cross.job.id == "use"
    assert cross.flow.path == "github.event.comment.body"
    assert cross.flow.depth >= 4, cross.flow.chain


def test_unreachable_payload_path_is_ignored():
    # The workflow only runs on push, so there is no issue payload to control.
    assert sinks("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.title }}
""") == []


def test_push_commit_message_is_reachable_on_push():
    hits = sinks("""
on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.head_commit.message }}
""")
    assert len(hits) == 1


def test_safe_contexts_are_not_sources():
    assert sinks("""
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ github.event.issue.number }} ${{ github.actor }} ${{ github.sha }}
""") == []


def test_predicate_use_does_not_propagate():
    assert sinks("""
on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ contains(github.event.comment.body, '/deploy') }}"
""") == []


def test_github_script_input_is_a_sink():
    hits = sinks("""
on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.comment.body }}")
""")
    assert [h.kind for h in hits] == [taint.SINK_SCRIPT_INPUT]


def test_flow_lines_point_at_real_source_lines():
    text = """
on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo hello
          echo ${{ github.event.issue.title }}
"""
    hit = sinks(text)[0]
    assert text.splitlines()[hit.line - 1].strip().startswith("echo ${{")
