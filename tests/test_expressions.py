from ghast import expr


def paths(value):
    return [r.path for r in expr.refs(value)]


def test_simple_reference():
    assert paths("${{ github.event.issue.title }}") == ["github.event.issue.title"]


def test_index_normalises_to_star():
    assert paths("${{ github.event.commits[0].message }}") == ["github.event.commits.*.message"]
    assert paths("${{ github.event.commits['a'].message }}") == ["github.event.commits.a.message"]


def test_function_names_are_not_references():
    assert paths("${{ format('{0}', github.actor) }}") == ["github.actor"]


def test_quoted_strings_are_skipped():
    assert paths("${{ 'github.event.issue.title' }}") == []


def test_predicate_arguments_are_marked():
    refs = expr.refs("${{ contains(github.event.comment.body, '/ok') }}")
    assert len(refs) == 1 and refs[0].in_predicate


def test_multiple_interpolations_keep_offsets():
    value = "a ${{ github.actor }} b ${{ github.ref }}"
    found = expr.refs(value)
    assert [r.path for r in found] == ["github.actor", "github.ref"]
    assert found[0].offset < found[1].offset


def test_literals_are_not_references():
    assert paths("${{ true && false }}") == []


def test_no_interpolation_returns_nothing():
    assert expr.refs("plain text") == []
    assert expr.refs(None) == []
