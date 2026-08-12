"""Deterministic JSON Schema export for knowledge_system contracts."""

from __future__ import annotations

import json
from pathlib import Path  # noqa: TC003

from pydantic import BaseModel  # noqa: TC002

from knowledge_system.domain import ApplyResult
from knowledge_system.domain import AssetRecord
from knowledge_system.domain import CaptureRecord
from knowledge_system.domain import ChunkRecord
from knowledge_system.domain import CollectionCatalog
from knowledge_system.domain import CollectionManifest
from knowledge_system.domain import ControlInspectionReport
from knowledge_system.domain import ControlInspectRequest
from knowledge_system.domain import ControlManifest
from knowledge_system.domain import ControlValidateRequest
from knowledge_system.domain import ControlValidationReport
from knowledge_system.domain import GrantRegistry
from knowledge_system.domain import GraphProjectionEdge
from knowledge_system.domain import InspectionReport
from knowledge_system.domain import MutationPlan
from knowledge_system.domain import MutationRequest
from knowledge_system.domain import NoteEnvelope
from knowledge_system.domain import OwnerGrant
from knowledge_system.domain import ProfileDefinition
from knowledge_system.domain import ProfileLockFile
from knowledge_system.domain import ProjectionRecipe
from knowledge_system.domain import ProjectionRecipeRegistry
from knowledge_system.domain import ProvenanceRegistry
from knowledge_system.domain import RetiredIdentityFile
from knowledge_system.domain import SemanticRelease
from knowledge_system.domain import SemanticReleaseRegistry
from knowledge_system.domain import SourceRecord
from knowledge_system.domain import SourceVersion
from knowledge_system.domain import TaskScopedGrant
from knowledge_system.domain import TrustDomainDefinition
from knowledge_system.domain import TrustDomainRegistry
from knowledge_system.domain import TrustEnclaveDefinition
from knowledge_system.domain import TrustPolicy
from knowledge_system.domain import ValidationReport


SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "apply-result": ApplyResult,
    "asset-record": AssetRecord,
    "capture-record": CaptureRecord,
    "chunk-record": ChunkRecord,
    "collection-catalog": CollectionCatalog,
    "collection-manifest": CollectionManifest,
    "control-inspection-report": ControlInspectionReport,
    "control-inspect-request": ControlInspectRequest,
    "control-manifest": ControlManifest,
    "control-validate-request": ControlValidateRequest,
    "control-validation-report": ControlValidationReport,
    "graph-projection-edge": GraphProjectionEdge,
    "grant-registry": GrantRegistry,
    "owner-grant": OwnerGrant,
    "inspection-report": InspectionReport,
    "mutation-plan": MutationPlan,
    "mutation-request": MutationRequest,
    "note-envelope": NoteEnvelope,
    "profile-definition": ProfileDefinition,
    "profile-lock": ProfileLockFile,
    "projection-recipe": ProjectionRecipe,
    "projection-recipe-registry": ProjectionRecipeRegistry,
    "provenance-registry": ProvenanceRegistry,
    "retired-identities": RetiredIdentityFile,
    "source-record": SourceRecord,
    "source-version": SourceVersion,
    "semantic-release-registry": SemanticReleaseRegistry,
    "semantic-release": SemanticRelease,
    "task-scoped-grant": TaskScopedGrant,
    "trust-domain-definition": TrustDomainDefinition,
    "trust-domain-registry": TrustDomainRegistry,
    "trust-enclave-definition": TrustEnclaveDefinition,
    "trust-policy": TrustPolicy,
    "validation-report": ValidationReport,
}


def rendered_schemas() -> dict[str, bytes]:
    """Return deterministic schema files keyed by filename."""
    return {
        f"{name}.schema.json": (
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for name, model in sorted(SCHEMA_MODELS.items())
    }


def export_schemas(destination: Path, *, check: bool = False) -> tuple[str, ...]:
    """Export schemas or return drifted filenames in check mode."""
    rendered = rendered_schemas()
    drifted: list[str] = []
    for filename, content in rendered.items():
        path = destination / filename
        if not path.exists() or path.read_bytes() != content:
            drifted.append(filename)
            if not check:
                destination.mkdir(parents=True, exist_ok=True)
                _ = path.write_bytes(content)
    extra = sorted(path.name for path in destination.glob("*.schema.json") if path.name not in rendered)
    drifted.extend(extra)
    return tuple(sorted(drifted))
