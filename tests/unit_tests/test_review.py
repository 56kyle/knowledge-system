# pyright: reportUnusedCallResult=false

from knowledge_system.review import compute_review_basis


def test_compute_review_basis_ignores_only_review_attestation_changes() -> None:
    first = b"---\nid: claim\ncreated_by: human\nreview:\n  status: unreviewed\n---\n# Claim\nBody\n"
    second = (
        b"---\nid: claim\ncreated_by: human\nreview:\n  status: reviewed\n  reviewed_by: owner\n  reviewed_at: 2026-01-01T00:00:00Z\n  basis: sha256:"
        + b"0" * 64
        + b"\n---\n# Claim\nBody\n"
    )

    assert compute_review_basis(first) == compute_review_basis(second)


def test_compute_review_basis_changes_for_material_metadata() -> None:
    first = b"---\nid: claim\ncreated_by: human\n---\n# Claim\nBody\n"
    second = b"---\nid: claim\ncreated_by: another-human\n---\n# Claim\nBody\n"

    assert compute_review_basis(first) != compute_review_basis(second)


def test_compute_review_basis_normalizes_line_endings() -> None:
    lf = b"---\nid: claim\ncreated_by: human\n---\n# Claim\nBody\n"
    crlf = lf.replace(b"\n", b"\r\n")
    assert compute_review_basis(lf) == compute_review_basis(crlf)
