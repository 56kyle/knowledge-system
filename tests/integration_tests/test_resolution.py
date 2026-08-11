# pyright: reportUnusedCallResult=false

from pathlib import Path

import pytest

from knowledge_system.domain import CatalogEntry
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import ResolutionContext
from knowledge_system.exceptions import AuthorizationError
from knowledge_system.exceptions import ReferenceResolutionError
from knowledge_system.resolution import parse_reference
from knowledge_system.resolution import resolve_reference
from tests.helpers import write_manifest
from tests.helpers import write_note


def test_resolve_reference_uses_identity_not_title_or_path(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    write_manifest(collection, collection_id="research")
    write_note(collection / "arbitrary" / "same-title.md", identity="stable-id", body="# Same Title\nText ^claim\n")
    catalog = CollectionCatalog(
        collections=(
            CatalogEntry(
                collection_id="research",
                manifest="collection/collection.yaml",
                trust_domains=frozenset({"work"}),
            ),
        )
    )
    context = ResolutionContext(catalog=catalog, catalog_root=str(tmp_path), allowed_collections=("research",))

    result = resolve_reference(parse_reference("note:research/stable-id#^claim"), context)

    assert Path(result.path) == collection / "arbitrary" / "same-title.md"


def test_resolve_reference_denies_before_disclosing_missing_collection(tmp_path: Path) -> None:
    context = ResolutionContext(
        catalog=CollectionCatalog(collections=()), catalog_root=str(tmp_path), allowed_collections=("allowed",)
    )

    with pytest.raises(AuthorizationError):
        resolve_reference(parse_reference("note:secret/missing"), context)


def test_resolve_reference_rejects_non_note_local_resolution(tmp_path: Path) -> None:
    context = ResolutionContext(catalog=CollectionCatalog(collections=()), catalog_root=str(tmp_path))
    with pytest.raises(ReferenceResolutionError):
        resolve_reference(parse_reference("capture:item"), context)


def test_resolve_reference_rejects_catalog_traversal_locator(tmp_path: Path) -> None:
    catalog = CollectionCatalog(
        collections=(
            CatalogEntry(
                collection_id="research",
                manifest="../outside/collection.yaml",
                trust_domains=frozenset({"work"}),
            ),
        )
    )
    context = ResolutionContext(catalog=catalog, catalog_root=str(tmp_path), allowed_collections=("research",))
    with pytest.raises(ReferenceResolutionError):
        resolve_reference(parse_reference("note:research/claim"), context)


def test_resolve_reference_rejects_file_locator_outside_allowlist(tmp_path: Path) -> None:
    manifest = tmp_path / "collection.yaml"
    manifest.write_text("version: 1\n", encoding="utf-8")
    catalog = CollectionCatalog(
        collections=(
            CatalogEntry(
                collection_id="research",
                manifest=manifest.as_uri(),
                trust_domains=frozenset({"work"}),
            ),
        )
    )
    context = ResolutionContext(catalog=catalog, catalog_root=str(tmp_path), allowed_collections=("research",))
    with pytest.raises(AuthorizationError):
        resolve_reference(parse_reference("note:research/claim"), context)


def test_resolve_reference_rejects_manifest_identity_mismatch(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    write_manifest(collection, collection_id="actual")
    write_note(collection / "claim.md", identity="claim")
    catalog = CollectionCatalog(
        collections=(
            CatalogEntry(
                collection_id="cataloged",
                manifest="collection/collection.yaml",
                trust_domains=frozenset({"work"}),
            ),
        )
    )
    context = ResolutionContext(catalog=catalog, catalog_root=str(tmp_path), allowed_collections=("cataloged",))
    with pytest.raises(ReferenceResolutionError):
        resolve_reference(parse_reference("note:cataloged/claim"), context)


def test_resolve_reference_rejects_catalog_trust_domain_mismatch(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    write_manifest(collection, collection_id="research", trust_domain="work")
    write_note(collection / "claim.md", identity="claim")
    catalog = CollectionCatalog(
        collections=(
            CatalogEntry(
                collection_id="research",
                manifest="collection/collection.yaml",
                trust_domains=frozenset({"public"}),
            ),
        )
    )
    context = ResolutionContext(catalog=catalog, catalog_root=str(tmp_path), allowed_collections=("research",))
    with pytest.raises(ReferenceResolutionError):
        resolve_reference(parse_reference("note:research/claim"), context)
