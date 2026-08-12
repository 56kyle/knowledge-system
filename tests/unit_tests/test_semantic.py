# pyright: reportUnusedCallResult=false

from hashlib import sha256
from pathlib import Path

import pytest

from knowledge_system.collection import inspect_root
from knowledge_system.domain import CollectionManifest
from knowledge_system.exceptions import ConfigurationError
from knowledge_system.semantic import load_semantic_bundle
from tests.helpers import write_builtin_locks
from tests.helpers import write_manifest


def _manifest(root: Path) -> CollectionManifest:
    manifest = inspect_root(root).manifest
    assert manifest is not None
    return manifest


def test_load_semantic_bundle_loads_exact_builtin_selection(tmp_path: Path) -> None:
    write_manifest(tmp_path, enabled_profiles={"flap": 1})
    bundle = load_semantic_bundle(tmp_path, _manifest(tmp_path))
    assert bundle.profiles == {}
    assert "related" in bundle.predicates
    assert bundle.input_digests.keys() == {"profiles.lock.yaml"}


def test_load_semantic_bundle_rejects_disabled_extra_lock(tmp_path: Path) -> None:
    write_manifest(tmp_path)
    write_builtin_locks(tmp_path, {"research": 1})
    with pytest.raises(ConfigurationError):
        load_semantic_bundle(tmp_path, _manifest(tmp_path))


def test_load_semantic_bundle_rejects_definition_digest_or_identity_mismatch(tmp_path: Path) -> None:
    definition = b"version: 1\nid: actual\nfield_prefix: custom_\nfields: []\n"
    (tmp_path / "custom.yaml").write_bytes(definition)
    write_manifest(tmp_path, enabled_profiles={"expected": 1})
    lock = tmp_path / "profiles.lock.yaml"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            'sha256: "' + "0" * 64 + '"',
            f'sha256: "{sha256(definition).hexdigest()}"\n    path: custom.yaml',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_semantic_bundle(tmp_path, _manifest(tmp_path))


def test_load_semantic_bundle_rejects_definition_path_escape(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-profile.yaml"
    content = b"version: 1\nid: custom\nfield_prefix: custom_\nfields: []\n"
    outside.write_bytes(content)
    write_manifest(tmp_path, enabled_profiles={"custom": 1})
    lock = tmp_path / "profiles.lock.yaml"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace(
            'sha256: "' + "0" * 64 + '"',
            f'sha256: "{sha256(content).hexdigest()}"\n    path: ../{outside.name}',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_semantic_bundle(tmp_path, _manifest(tmp_path))


def test_load_semantic_bundle_loads_custom_vocabulary_as_only_selected_vocabulary(tmp_path: Path) -> None:
    definition = (
        b"version: 1\nid: custom-vocab\nfield_prefix: custom_\nfields: []\n"
        b"predicates:\n  - name: future_link\n    prospective_allowed: true\n"
    )
    (tmp_path / "vocabulary.yaml").write_bytes(definition)
    write_manifest(tmp_path)
    manifest_path = tmp_path / "collection.yaml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace("vocabulary: core@1", "vocabulary: custom-vocab"),
        encoding="utf-8",
    )
    (tmp_path / "profiles.lock.yaml").write_text(
        f"""version: 1
profiles: []
relation_vocabularies:
  - identifier: custom-vocab
    version: 1
    sha256: "{sha256(definition).hexdigest()}"
    path: vocabulary.yaml
""",
        encoding="utf-8",
    )
    bundle = load_semantic_bundle(tmp_path, _manifest(tmp_path))
    assert tuple(bundle.predicates) == ("future_link",)
