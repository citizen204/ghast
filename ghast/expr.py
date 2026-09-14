"""Parsing of GitHub Actions ``${{ }}`` expressions.

We do not need a full evaluator.  We need two things:

1. every ``${{ ... }}`` span in a string, with its byte offset, and
2. every *context reference* inside that span (``github.event.issue.title``,
   ``steps.foo.outputs.bar``, ``env.NAME`` ...), normalised so that a catalog
   lookup works.

Index expressions collapse to ``*`` so that ``github.event.commits[0].message``
and ``github.event.commits.*.message`` compare equal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence

# ${{ ... }} — non-greedy, tolerant of newlines inside the expression.
_INTERP_RE = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")

#: Functions whose result is still attacker-influenced if any argument is.
PROPAGATING_FUNCS = frozenset(
    {"format", "join", "tojson", "fromjson", "trim", "replace", "lower", "upper"}
)
#: Functions that reduce a value to a boolean — taint does not survive them.
PREDICATE_FUNCS = frozenset({"contains", "startswith", "endswith", "success", "failure",
                             "cancelled", "always", "hashfiles"})


@dataclass(frozen=True)
class ContextRef:
    """A single context reference inside an expression."""

    path: str                  # normalised, e.g. "github.event.issue.title"
    raw: str                   # exactly as written
    offset: int                # byte offset within the *containing string*
    in_predicate: bool = False  # appeared only as an argument to contains()/etc.

    @property
    def root(self) -> str:
        return self.path.split(".", 1)[0]

    def startswith(self, prefix: str) -> bool:
        return self.path == prefix or self.path.startswith(prefix + ".")


@dataclass
class Interpolation:
    """One ``${{ ... }}`` occurrence."""

    text: str                   # the inner expression
    start: int                  # offset of the "$" in the containing string
    end: int                    # offset just past "}}"
    refs: List[ContextRef] = field(default_factory=list)

    @property
    def raw(self) -> str:
        return "${{" + self.text + "}}"


def _normalise(raw: str) -> str:
    """``a['b'][0].c`` -> ``a.b.*.c``"""
    out: List[str] = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == "[":
            depth = 1
            j = i + 1
            while j < n and depth:
                if raw[j] == "[":
                    depth += 1
                elif raw[j] == "]":
                    depth -= 1
                j += 1
            inner = raw[i + 1 : j - 1].strip()
            m = re.fullmatch(r"""['"]([A-Za-z_][A-Za-z0-9_-]*)['"]""", inner)
            out.append("." + m.group(1) if m else ".*")
            i = j
            continue
        out.append(ch)
        i += 1
    joined = "".join(out)
    joined = re.sub(r"\s+", "", joined)
    return joined


def _scan_refs(expr: str, base_offset: int) -> List[ContextRef]:
    """Pull context references out of one expression body."""
    refs: List[ContextRef] = []
    i = 0
    n = len(expr)
    # Track which character ranges sit inside a predicate function call, so
    # `contains(github.event.comment.body, 'x')` is not treated as a data flow.
    predicate_spans = _predicate_spans(expr)

    while i < n:
        ch = expr[i]
        if ch in "'\"":
            quote = ch
            i += 1
            while i < n:
                if expr[i] == quote:
                    # '' is an escaped quote in GitHub expressions
                    if i + 1 < n and expr[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        m = _IDENT_RE.match(expr, i)
        if not m:
            i += 1
            continue
        start = m.start()
        j = m.end()
        # A bare identifier immediately followed by "(" is a function call.
        k = j
        while k < n and expr[k] == " ":
            k += 1
        if k < n and expr[k] == "(":
            i = j
            continue
        # Consume the dotted / indexed path.
        while j < n:
            if expr[j] == ".":
                nxt = _IDENT_RE.match(expr, j + 1)
                if nxt:
                    j = nxt.end()
                    continue
                if j + 1 < n and expr[j + 1] == "*":
                    j += 2
                    continue
                break
            if expr[j] == "[":
                depth = 1
                j += 1
                while j < n and depth:
                    if expr[j] == "[":
                        depth += 1
                    elif expr[j] == "]":
                        depth -= 1
                    j += 1
                continue
            break
        raw = expr[start:j]
        path = _normalise(raw)
        root = path.split(".", 1)[0]
        if root in _KEYWORDS:
            i = j
            continue
        refs.append(
            ContextRef(
                path=path,
                raw=raw,
                offset=base_offset + start,
                in_predicate=any(a <= start < b for a, b in predicate_spans),
            )
        )
        i = j
    return refs


_KEYWORDS = frozenset({"true", "false", "null", "and", "or", "not"})


def _predicate_spans(expr: str) -> List[Sequence[int]]:
    spans: List[Sequence[int]] = []
    for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", expr):
        if m.group(1).lower() not in PREDICATE_FUNCS:
            continue
        depth = 1
        i = m.end()
        while i < len(expr) and depth:
            if expr[i] == "(":
                depth += 1
            elif expr[i] == ")":
                depth -= 1
            i += 1
        spans.append((m.end(), i))
    return spans


def interpolations(value: object) -> List[Interpolation]:
    """Every ``${{ }}`` in ``value`` (non-strings yield nothing)."""
    if not isinstance(value, str) or "${{" not in value:
        return []
    out: List[Interpolation] = []
    for m in _INTERP_RE.finditer(value):
        body = m.group(1)
        interp = Interpolation(text=body, start=m.start(), end=m.end())
        interp.refs = _scan_refs(body, m.start() + 3)
        out.append(interp)
    return out


def refs(value: object) -> List[ContextRef]:
    """Flattened context references across every interpolation in ``value``."""
    out: List[ContextRef] = []
    for interp in interpolations(value):
        out.extend(interp.refs)
    return out


def iter_strings(node: object, path: str = "") -> Iterator[Sequence[object]]:
    """Walk a parsed YAML tree yielding ``(dotted_path, string_value)``."""
    if isinstance(node, str):
        yield (path, node)
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from iter_strings(value, "{}.{}".format(path, key) if path else str(key))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            yield from iter_strings(value, "{}[{}]".format(path, idx))


def has_interpolation(value: object) -> bool:
    return isinstance(value, str) and "${{" in value
