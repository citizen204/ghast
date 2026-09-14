"""YAML loading that preserves source positions.

PyYAML throws away line/column information once a document is constructed,
which is useless for a security tool: a finding that cannot point at a line
is a finding nobody will fix.  We subclass ``SafeLoader`` and construct
position-carrying containers instead of plain ``dict``/``list``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import yaml


class PosDict(dict):
    """A ``dict`` that remembers where each key was written."""

    __slots__ = ("line", "col", "key_pos", "val_pos")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.line: int = 1
        self.col: int = 1
        # key -> (line, col) of the key token
        self.key_pos: Dict[Any, Tuple[int, int]] = {}
        # key -> (line, col) of the value token
        self.val_pos: Dict[Any, Tuple[int, int]] = {}

    def pos_of(self, key: Any) -> Tuple[int, int]:
        return self.key_pos.get(key, (self.line, self.col))

    def value_pos_of(self, key: Any) -> Tuple[int, int]:
        return self.val_pos.get(key, self.pos_of(key))


class PosList(list):
    __slots__ = ("line", "col", "item_pos")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.line: int = 1
        self.col: int = 1
        self.item_pos: List[Tuple[int, int]] = []

    def pos_of(self, index: int) -> Tuple[int, int]:
        if 0 <= index < len(self.item_pos):
            return self.item_pos[index]
        return (self.line, self.col)


class PosLoader(yaml.SafeLoader):
    """SafeLoader that produces :class:`PosDict` / :class:`PosList`."""


def _construct_mapping(loader: "PosLoader", node: yaml.MappingNode) -> PosDict:
    loader.flatten_mapping(node)
    mapping = PosDict()
    mapping.line = node.start_mark.line + 1
    mapping.col = node.start_mark.column + 1
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        # GitHub treats `on:` specially; YAML 1.1 would turn it into True.
        if isinstance(key, bool):
            key = "on" if key is True else "off"
        try:
            hash(key)
        except TypeError:
            key = str(key)
        value = loader.construct_object(value_node, deep=True)
        mapping[key] = value
        mapping.key_pos[key] = (key_node.start_mark.line + 1, key_node.start_mark.column + 1)
        mapping.val_pos[key] = (value_node.start_mark.line + 1, value_node.start_mark.column + 1)
    return mapping


def _construct_sequence(loader: "PosLoader", node: yaml.SequenceNode) -> PosList:
    seq = PosList()
    seq.line = node.start_mark.line + 1
    seq.col = node.start_mark.column + 1
    for child in node.value:
        seq.append(loader.construct_object(child, deep=True))
        seq.item_pos.append((child.start_mark.line + 1, child.start_mark.column + 1))
    return seq


PosLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
PosLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence)


def load(text: str) -> Optional[Any]:
    """Parse ``text``; returns ``None`` for an empty document."""
    return yaml.load(text, Loader=PosLoader)


def offset_line(base_line: int, block_text: str, needle_index: int) -> int:
    """Map an index inside a block scalar back to an absolute file line.

    ``run:`` bodies are multi-line strings; when a sink is found at some
    character offset we want the line *inside* the script, not the line the
    ``run:`` key sits on.
    """
    return base_line + block_text.count("\n", 0, max(needle_index, 0))
