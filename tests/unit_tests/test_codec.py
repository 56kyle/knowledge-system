# pyright: reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from knowledge_system.codec import _scan_body
from knowledge_system.codec import dump_yaml_mapping
from knowledge_system.codec import load_yaml_mapping
from knowledge_system.codec import parse_markdown
from knowledge_system.codec import render_markdown
from knowledge_system.exceptions import ConfigurationError


if TYPE_CHECKING:
    from collections.abc import MutableMapping


def test_load_yaml_mapping_preserves_comments_and_quoted_scalars() -> None:
    source = '# retained\ntitle: "yes"\nitems:\n  - one\n'

    mapping = load_yaml_mapping(source)
    mapping["added"] = True

    rendered = dump_yaml_mapping(mapping)
    assert rendered == '# retained\ntitle: "yes"\nitems:\n- one\nadded: true\n'


def test_load_yaml_mapping_rejects_duplicate_keys() -> None:
    with pytest.raises(ConfigurationError):
        load_yaml_mapping("id: one\nid: two\n")


def test_load_yaml_mapping_rejects_non_mapping() -> None:
    with pytest.raises(ConfigurationError):
        load_yaml_mapping("- one\n- two\n")


def test_parse_markdown_retains_frontmatter_offset_and_supported_constructs() -> None:
    content = (
        b"---\r\nid: unicode-note\r\ncreated_by: human\r\n---\r\n"
        b"# Caf\xc3\xa9\r\n> [!NOTE]\r\n> [[Other Note]]\r\n"
        b"A [source](https://example.test/page) and <https://example.test/auto>. ^claim-1\r\n"
    )

    document = parse_markdown(content)

    assert document.body_start_line == 5
    assert document.headings == ((5, 1, "Café"),)
    assert document.block_ids == ((8, "claim-1"),)
    assert document.links == (
        (7, "Other Note"),
        (8, "https://example.test/page"),
        (8, "https://example.test/auto"),
    )
    assert document.newline == "\r\n"


def test__scan_body_ignores_fences_inline_code_and_html_comments() -> None:
    body = """# Visible
`[[inline]]`
<!-- [[commented]] -->
```md
[[fenced]]
```
[[kept]]
"""

    headings, _blocks, links, diagnostics = _scan_body(body, 10)

    assert headings == [(10, 1, "Visible")]
    assert links == [(16, "kept")]
    assert diagnostics == []


@pytest.mark.parametrize(
    ("body", "diagnostic"),
    [
        ("[[missing\n", "malformed wiki link"),
        ("```\nbody\n", "unclosed fenced code block"),
    ],
)
def test__scan_body_reports_malformed_supported_constructs(body: str, diagnostic: str) -> None:
    *_observations, diagnostics = _scan_body(body, 1)
    assert any(message == diagnostic for _line, message in diagnostics)


def test_render_markdown_preserves_bom_newlines_and_body_bytes() -> None:
    original = b"\xef\xbb\xbf---\r\ntitle: Original\r\n---\r\n# Body\r\n\r\nText\r\n"
    document = parse_markdown(original)
    frontmatter: MutableMapping[str, object] = document.frontmatter or {}
    frontmatter["new"] = "field"

    rendered = render_markdown(document, frontmatter)

    assert rendered.startswith(b"\xef\xbb\xbf---\r\n")
    assert rendered.endswith(b"# Body\r\n\r\nText\r\n")
