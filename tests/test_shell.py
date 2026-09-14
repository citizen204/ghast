import pytest

from ghast import shell

EXEC_CASES = [
    ('echo "$V"', False),
    ("echo $V", False),
    ("echo '$V'", False),
    ("# echo $V", False),
    ('eval "$V"', True),
    ("eval $V", True),
    ('bash -c "$V"', True),
    ('sh -c "$V"', True),
    ('python3 -c "$V"', True),
    ("$V", True),
    ("$V --flag", True),
    ("sudo $V", True),
    ("timeout 30 $V", True),
    ("FOO=1 $V", True),
    ("X=$(echo $V)", False),
    ("echo `date` $V", False),
    ('if [ "$V" = "x" ]; then', False),
    ('echo "K=$V" >> $GITHUB_ENV', False),
    ("source $V", True),
    ("xargs $V", True),
    ('echo "${V}"', False),
    ("echo ${V:-default}", False),
]


@pytest.mark.parametrize("script,expected", EXEC_CASES)
def test_execution_detection(script, expected):
    uses = shell.find_var_uses(script, "V")
    assert any(u.is_execution for u in uses) is expected, script


def test_single_quotes_suppress_expansion_entirely():
    assert shell.find_var_uses("echo '$V'", "V") == []


def test_argument_injection_only_when_unquoted():
    assert any(u.is_argument_injection for u in shell.find_var_uses("curl $V", "V"))
    assert not any(u.is_argument_injection for u in shell.find_var_uses('curl "$V"', "V"))


def test_env_file_writes_are_found():
    script = 'echo "A=1" >> $GITHUB_ENV\necho "b=2" >> "$GITHUB_OUTPUT"\necho "/x" >> $GITHUB_PATH'
    writes = shell.find_env_file_writes(script)
    assert [w.target for w in writes] == ["GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"]
    assert writes[0].names == ["A"]


def test_line_numbers_are_one_based():
    uses = shell.find_var_uses("first\nsecond $V\n", "V")
    assert uses[0].line == 2


# --- regression: quoting decides whether command position is even possible ---

QUOTED_ASSIGNMENT_CASES = [
    # rtk-ai/rtk next-release.yml did exactly this, and it is the *correct*
    # pattern: the payload value is carried in env and read inside quotes.
    'ENTRY="- ${V} [#${N}](${U})"',
    'ENTRY="- $V"',
    'MSG="prefix $V suffix"',
    'BODY="$V"',
]


@pytest.mark.parametrize("script", QUOTED_ASSIGNMENT_CASES)
def test_quoted_assignment_is_not_command_position(script):
    """`NAME="... $V ..."` is a string assignment, not an invocation.

    The assignment-prefix regex matched `ENTRY="-` plus a space and concluded
    the read sat in command position, so ghast reported a hardened workflow as
    a high-severity execution sink.
    """
    uses = shell.find_var_uses(script, "V")
    assert uses, script
    assert not any(u.is_execution for u in uses), script


def test_single_quoted_assignment_has_no_expansion_at_all():
    """Stronger than "not execution": in single quotes nothing expands, so
    there is no read to classify."""
    assert shell.find_var_uses("LIT='- $V'", "V") == []


def test_unquoted_assignment_is_also_not_execution():
    assert not any(u.is_execution for u in shell.find_var_uses("VAR=$V", "V"))


def test_eval_still_wins_over_quoting():
    """Quoting does not save you when the whole span is handed to a parser."""
    assert any(u.is_execution for u in shell.find_var_uses('eval "$V"', "V"))
    assert any(u.is_execution for u in shell.find_var_uses('bash -c "$V"', "V"))
