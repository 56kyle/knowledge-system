"""Markdown and YAML codecs for the knowledge_system package."""

from __future__ import annotations

import re
from collections.abc import MutableMapping  # noqa: TC003
from dataclasses import dataclass
from io import StringIO
from typing import cast

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.constructor import DuplicateKeyError
from ruamel.yaml.error import YAMLError

from knowledge_system.exceptions import ConfigurationError


MAX_MARKDOWN_BYTES = 10_000_000
MAX_FRONTMATTER_BYTES = 1_000_000
_FRONTMATTER_DELIMITER = "---"
_FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_BLOCK_ID = re.compile(r"(?<!\S)\^([A-Za-z0-9][A-Za-z0-9_-]*)\s*$")
_WIKI_LINK = re.compile(r"(?<!!)\[\[([^\]|]+)(?:\|[^\]]*)?\]\]")
_MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^\s)]+)(?:\s+['\"].*?['\"])?\)")
_AUTOLINK = re.compile(r"<(https?://[^>]+)>")
_RAW_URL = re.compile(r"(?<![<(])(https?://[^\s<>]+)")
_INLINE_CODE = re.compile(r"(`+)(.*?)\1")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


@dataclass(frozen=True)
class MarkdownDocument:
    """Lossless Markdown split with scanner observations."""

    original: bytes
    text: str
    newline: str
    bom: bool
    frontmatter: MutableMapping[str, object] | None
    frontmatter_text: str | None
    body: str
    body_start_line: int
    headings: tuple[tuple[int, int, str], ...]
    block_ids: tuple[tuple[int, str], ...]
    links: tuple[tuple[int, str], ...]
    diagnostics: tuple[tuple[int, str], ...]


def _yaml() -> YAML:
    """Return the isolated round-trip YAML 1.2 codec."""
    parser = YAML(typ="rt")
    parser.version = (1, 2)
    parser.allow_duplicate_keys = False
    parser.preserve_quotes = True
    parser.default_flow_style = False
    return parser


def load_yaml_mapping(text: str, *, source: str = "YAML") -> MutableMapping[str, object]:
    """Load one closed YAML mapping with duplicate keys rejected."""
    try:
        loaded = _yaml().load(text)  # pyright: ignore[reportAny, reportUnknownMemberType]
    except (DuplicateKeyError, YAMLError) as error:
        raise ConfigurationError(f"invalid {source}: {error}") from error
    if loaded is None:
        return cast("MutableMapping[str, object]", CommentedMap())
    if not isinstance(loaded, CommentedMap):
        raise ConfigurationError(f"{source} must contain one mapping")
    return cast("MutableMapping[str, object]", loaded)


def dump_yaml_mapping(mapping: MutableMapping[str, object]) -> str:
    """Render a round-trip mapping without discarding local style."""
    stream = StringIO()
    emitter = _yaml()
    emitter.version = None
    emitter.dump(mapping, stream)  # pyright: ignore[reportUnknownMemberType]
    return stream.getvalue()


def plain_mapping(mapping: MutableMapping[str, object]) -> dict[str, object]:
    """Convert a round-trip mapping into a Pydantic boundary value."""
    return dict(mapping)


def new_yaml_mapping(values: dict[str, object] | None = None) -> MutableMapping[str, object]:
    """Create a round-trip mapping behind a typed mutable-mapping boundary."""
    return cast("MutableMapping[str, object]", CommentedMap(values or {}))


def insert_yaml_field(
    mapping: MutableMapping[str, object],
    position: int,
    key: str,
    value: object,
) -> None:
    """Insert a field at a stable position when round-trip insertion is available."""
    if isinstance(mapping, CommentedMap):
        mapping.insert(position, key, value)  # pyright: ignore[reportUnknownMemberType]
    else:
        mapping[key] = value


def parse_markdown(content: bytes) -> MarkdownDocument:
    """Parse bounded UTF-8 Markdown while retaining physical line numbers."""
    if len(content) > MAX_MARKDOWN_BYTES:
        raise ConfigurationError(f"Markdown exceeds {MAX_MARKDOWN_BYTES} bytes")
    bom = content.startswith(b"\xef\xbb\xbf")
    encoded = content[3:] if bom else content
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ConfigurationError("Markdown must be UTF-8") from error
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.splitlines(keepends=True)
    frontmatter: MutableMapping[str, object] | None = None
    frontmatter_text: str | None = None
    body_start_line = 1
    body = text
    diagnostics: list[tuple[int, str]] = []
    if lines and lines[0].rstrip("\r\n") == _FRONTMATTER_DELIMITER:
        closing: int | None = next(
            (index for index, line in enumerate(lines[1:], start=1) if line.rstrip("\r\n") == _FRONTMATTER_DELIMITER),
            None,
        )
        if closing is None:
            diagnostics.append((1, "frontmatter opening delimiter has no closing delimiter"))
        else:
            frontmatter_text = "".join(lines[1:closing])
            if len(frontmatter_text.encode("utf-8")) > MAX_FRONTMATTER_BYTES:
                diagnostics.append((1, f"frontmatter exceeds {MAX_FRONTMATTER_BYTES} bytes"))
            else:
                try:
                    frontmatter = load_yaml_mapping(frontmatter_text, source="frontmatter")
                except ConfigurationError as error:
                    diagnostics.append((1, str(error)))
            body_start_line = closing + 2
            body = "".join(lines[closing + 1 :])
    headings, block_ids, links, scan_diagnostics = _scan_body(body, body_start_line)
    diagnostics.extend(scan_diagnostics)
    return MarkdownDocument(
        original=content,
        text=text,
        newline=newline,
        bom=bom,
        frontmatter=frontmatter,
        frontmatter_text=frontmatter_text,
        body=body,
        body_start_line=body_start_line,
        headings=tuple(headings),
        block_ids=tuple(block_ids),
        links=tuple(links),
        diagnostics=tuple(diagnostics),
    )


def _scan_body(  # noqa: C901
    body: str,
    first_line: int,
) -> tuple[
    list[tuple[int, int, str]],
    list[tuple[int, str]],
    list[tuple[int, str]],
    list[tuple[int, str]],
]:
    """Scan supported Markdown constructs without claiming CommonMark completeness."""
    uncommented = _HTML_COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), body)
    headings: list[tuple[int, int, str]] = []
    block_ids: list[tuple[int, str]] = []
    links: list[tuple[int, str]] = []
    diagnostics: list[tuple[int, str]] = []
    fence_marker: str | None = None
    fence_length = 0
    for offset, raw_line in enumerate(uncommented.splitlines(), start=0):
        line_number = first_line + offset
        fence = _FENCE.match(raw_line)
        if fence:
            marker = fence.group(1)
            if fence_marker is None:
                fence_marker = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_marker and len(marker) >= fence_length:
                fence_marker = None
                fence_length = 0
            continue
        if fence_marker is not None:
            continue
        line = _INLINE_CODE.sub("", raw_line)
        heading = _HEADING.match(line)
        if heading:
            headings.append((line_number, len(heading.group(1)), heading.group(2).strip()))
        block = _BLOCK_ID.search(line)
        if block:
            block_ids.append((line_number, block.group(1)))
        for pattern in (_WIKI_LINK, _MARKDOWN_LINK, _AUTOLINK, _RAW_URL):
            links.extend((line_number, match.group(1).rstrip(".,;:")) for match in pattern.finditer(line))
        if "[[" in line and "]]" not in line:
            diagnostics.append((line_number, "malformed wiki link"))
        if line.count("[") > line.count("]"):
            diagnostics.append((line_number, "possibly malformed Markdown link"))
    if fence_marker is not None:
        diagnostics.append((first_line + len(uncommented.splitlines()) - 1, "unclosed fenced code block"))
    return headings, block_ids, links, diagnostics


def render_markdown(
    document: MarkdownDocument,
    frontmatter: MutableMapping[str, object],
) -> bytes:
    """Render changed frontmatter while preserving body bytes and newline style."""
    rendered = dump_yaml_mapping(frontmatter)
    rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
    if document.newline != "\n":
        rendered = rendered.replace("\n", document.newline)
    text = f"---{document.newline}{rendered}---{document.newline}{document.body}"
    encoded = text.encode("utf-8")
    return b"\xef\xbb\xbf" + encoded if document.bom else encoded
