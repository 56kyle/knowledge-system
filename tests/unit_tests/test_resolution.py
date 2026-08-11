# pyright: reportUnusedCallResult=false

import pytest

from knowledge_system.domain import CanonicalReference
from knowledge_system.exceptions import ReferenceSyntaxError
from knowledge_system.resolution import parse_reference


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "note:research/claim-one#^evidence-2",
            CanonicalReference(scheme="note", collection="research", identifier="claim-one", block="evidence-2"),
        ),
        ("source:book/one", CanonicalReference(scheme="source", identifier="book/one")),
        ("source-version:book.v2", CanonicalReference(scheme="source-version", identifier="book.v2")),
        ("capture:cap-1", CanonicalReference(scheme="capture", identifier="cap-1")),
        ("asset:image.png", CanonicalReference(scheme="asset", identifier="image.png")),
        ("workflow:item-1", CanonicalReference(scheme="workflow", identifier="item-1")),
    ],
)
def test_parse_reference_with_valid(value: str, expected: CanonicalReference) -> None:
    assert parse_reference(value) == expected


@pytest.mark.parametrize(
    "value",
    ["Note:research/claim", "note:Research/claim", "note:research/Claim", "note:research/claim#heading", "../claim"],
)
def test_parse_reference_with_invalid(value: str) -> None:
    with pytest.raises(ReferenceSyntaxError):
        parse_reference(value)
