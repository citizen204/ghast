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
