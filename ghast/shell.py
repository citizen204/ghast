"""Light-weight shell reasoning for ``run:`` blocks.

The point is severity accuracy, not emulation.  Three questions matter:

* Is a tainted value spliced in as *text* before the shell parses it?
  ``run: echo ${{ github.event.issue.title }}`` -- always arbitrary execution.
* Is it read back from an environment variable, and if so, is it quoted?
  ``run: echo "$TITLE"`` is the documented fix and must never be flagged.
  ``run: echo $TITLE`` is argument injection, not command execution.
  ``run: eval $TITLE`` is execution again.
* Does the script write attacker data into ``$GITHUB_ENV`` / ``$GITHUB_PATH``?
  Those files are parsed line by line, so a newline in the value is a free
  environment or PATH overwrite -- and ``NODE_OPTIONS`` turns that into code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set

QUOTE_NONE = "none"
QUOTE_SINGLE = "single"
QUOTE_DOUBLE = "double"

#: Patterns which, when they appear on the same line *before* a variable
#: read, mean the variable's own content is re-parsed as code.
_EVAL_PATTERNS = (
    re.compile(r"(^|[;&|(]\s*|\s)eval\s"),
    re.compile(r"(^|[;&|(]\s*)(source|\.)\s"),
    re.compile(r"\b(ba|z|k)?sh\s+(-[a-z]*c|--command)\b"),
    re.compile(r"\b(python3?|perl|ruby|node|deno)\s+-(c|e)\b"),
    re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE),
    re.compile(r"\bxargs\b"),
)

#: Commands where an unquoted variable becomes attacker-chosen *flags*.
_ARG_INJECTION_COMMANDS = (
    "curl", "wget", "git", "rsync", "ssh", "scp", "tar", "docker", "gh", "aws",
    "kubectl", "npm", "pip", "find", "rm", "cp", "mv", "chmod", "chown",
)


@dataclass
class VarUse:
    name: str
    offset: int
    quoting: str
    in_eval: bool
    line: int           # 1-based line within the script
    line_text: str

    @property
    def is_execution(self) -> bool:
        """Does reading this variable here let the attacker run commands?"""
        if self.in_eval:
            return True
        # Inside double quotes the shell still expands $(...) and ``, but the
        # *variable's* own content is not re-parsed, so this is safe.
        return False

    @property
    def is_argument_injection(self) -> bool:
        if self.quoting != QUOTE_NONE or self.in_eval:
            return False
        stripped = self.line_text.strip().lstrip("$( ").lower()
        return any(stripped.startswith(cmd) or " {} ".format(cmd) in stripped
                   for cmd in _ARG_INJECTION_COMMANDS)


def quote_map(script: str) -> List[str]:
    """Quoting state at every character offset."""
    states: List[str] = []
    state = QUOTE_NONE
    escaped = False
    in_comment = False
    for ch in script:
        if in_comment:
            states.append("comment")
            if ch == "\n":
                in_comment = False
            continue
        states.append(state)
        if escaped:
            escaped = False
            continue
        if ch == "\\" and state != QUOTE_SINGLE:
            escaped = True
            continue
        if state == QUOTE_NONE:
            if ch == "'":
                state = QUOTE_SINGLE
            elif ch == '"':
                state = QUOTE_DOUBLE
            elif ch == "#":
                in_comment = True
                states[-1] = "comment"
        elif state == QUOTE_SINGLE and ch == "'":
            state = QUOTE_NONE
        elif state == QUOTE_DOUBLE and ch == '"':
            state = QUOTE_NONE
    return states


def _prefix_is_eval(prefix_line: str) -> bool:
    """Does the text before this read on the same line re-parse its value?"""
    lowered = prefix_line.lower()
    if any(pattern.search(lowered) for pattern in _EVAL_PATTERNS):
        return True
    # A variable sitting in command position *is* the command: `$CMD arg`.
    return _is_command_position(prefix_line)


_ASSIGN_PREFIX = re.compile(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*$")


def _is_command_position(prefix_line: str) -> bool:
    """True when nothing but separators/assignments precedes the read."""
    tail = prefix_line
    for sep in (";", "|", "&", "(", "{", "\n"):
        idx = tail.rfind(sep)
        if idx != -1:
            tail = tail[idx + 1:]
    tail = tail.lstrip("$")
    # Strip wrappers that simply exec their argument: `sudo $CMD`, `env $CMD`.
    while True:
        m = _WRAPPER_RE.match(tail)
        if not m:
            break
        tail = tail[m.end():]
    return bool(_ASSIGN_PREFIX.match(tail))


_WRAPPER_RE = re.compile(
    r"^\s*(?:sudo|doas|env|exec|command|nohup|time|timeout|nice|ionice|stdbuf|"
    r"setsid|xargs)\s+(?:-\S+\s+|\d+\s+)*"
)


def _line_of(script: str, offset: int) -> Sequence[object]:
    line_no = script.count("\n", 0, offset) + 1
    start = script.rfind("\n", 0, offset) + 1
    end = script.find("\n", offset)
    if end == -1:
        end = len(script)
    return (line_no, script[start:end])


def find_var_uses(script: str, name: str) -> List[VarUse]:
    """Every read of environment variable ``name`` inside ``script``."""
    if not script or not name:
        return []
    escaped = re.escape(name)
    pattern = re.compile(
        r"\$\{{{0}\}}|\$\{{{0}[:#%/\[][^}}]*\}}|\$\{{{0}\b|\${0}\b|\$env:{0}\b|%{0}%".format(escaped),
        re.IGNORECASE if False else 0,
    )
    states = quote_map(script)
    uses: List[VarUse] = []
    for m in pattern.finditer(script):
        offset = m.start()
        state = states[offset] if offset < len(states) else QUOTE_NONE
        if state == "comment":
            continue
        if state == QUOTE_SINGLE:
            # '$FOO' is a literal in POSIX shells; nothing expands.
            continue
        line_no, line_text = _line_of(script, offset)
        line_start = script.rfind("\n", 0, offset) + 1
        prefix_line = script[line_start:offset]
        in_eval = _prefix_is_eval(prefix_line)
        uses.append(
            VarUse(
                name=name,
                offset=offset,
                quoting=state,
                in_eval=in_eval,
                line=int(line_no),
                line_text=str(line_text),
            )
        )
    return uses


@dataclass
class EnvFileWrite:
    """A line that appends to one of the runner's magic files."""

    target: str         # GITHUB_ENV | GITHUB_OUTPUT | GITHUB_PATH | GITHUB_STEP_SUMMARY
    names: List[str]    # variable / output names assigned, when determinable
    offset: int
    line: int
    line_text: str


_ENV_FILE_RE = re.compile(
    r"^(?P<body>.*?)>>\s*[\"']?\$\{?(?P<target>GITHUB_ENV|GITHUB_OUTPUT|GITHUB_PATH|GITHUB_STEP_SUMMARY)\}?[\"']?\s*$"
)
_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=")
_HEREDOC_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*<<\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)")


def find_env_file_writes(script: str) -> List[EnvFileWrite]:
    writes: List[EnvFileWrite] = []
    offset = 0
    for line_no, raw_line in enumerate(script.splitlines(), start=1):
        line = raw_line.strip()
        m = _ENV_FILE_RE.match(line)
        if m:
            body = m.group("body")
            names = _ASSIGN_RE.findall(body)
            hd = _HEREDOC_NAME_RE.findall(body)
            names.extend(n for n, _ in hd)
            writes.append(
                EnvFileWrite(
                    target=m.group("target"),
                    names=list(dict.fromkeys(names)),
                    offset=offset,
                    line=line_no,
                    line_text=raw_line,
                )
            )
        offset += len(raw_line) + 1
    return writes


def heredoc_blocks(script: str) -> List[Sequence[object]]:
    """``NAME<<EOF`` ... ``EOF`` regions written to an env file.

    Returned as ``(name, start_line, end_line)``.  Used to decide whether a
    tainted value lands inside a delimited block (the documented multi-line
    pattern) which an attacker can still escape by emitting the delimiter.
    """
    out: List[Sequence[object]] = []
    pending: Optional[Sequence[object]] = None
    for line_no, raw in enumerate(script.splitlines(), start=1):
        stripped = raw.strip()
        if pending is None:
            m = re.search(r"([A-Za-z_][A-Za-z0-9_-]*)\s*<<\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", stripped)
            if m and (">>" in stripped or "GITHUB_" in stripped or stripped.startswith("echo")):
                pending = (m.group(1), m.group(2), line_no)
            continue
        name, delim, start = pending  # type: ignore[misc]
        if stripped == delim:
            out.append((name, start, line_no))
            pending = None
    return out


def shell_is_powershell(shell: Optional[str]) -> bool:
    return bool(shell) and str(shell).lower().split()[0] in {"pwsh", "powershell"}


def referenced_env_names(script: str, candidates: Set[str]) -> Set[str]:
    return {name for name in candidates if find_var_uses(script, name)}
