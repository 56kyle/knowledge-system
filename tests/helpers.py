# pyright: reportUnusedCallResult=false

from collections.abc import Iterable
from pathlib import Path

from knowledge_system.profiles import BUILTIN_LOCK_DIGESTS


def write_manifest(
    root: Path,
    *,
    collection_id: str = "local-notes",
    trust_domain: str = "work",
    note_roots: Iterable[str] = (".",),
    enabled_profiles: dict[str, int] | None = None,
    trust_policy: str | None = None,
    trust_policy_id: str | None = None,
) -> None:
    profiles = enabled_profiles or {}
    roots_yaml = "\n".join(f"      - {value}" for value in note_roots)
    enabled_yaml = "\n".join(f"      {name}: {version}" for name, version in profiles.items()) or "      {}"
    references = ""
    if trust_policy:
        references = f"\nreferences:\n  trust_policy: {trust_policy}"
        if trust_policy_id:
            references += f"\n  trust_policy_id: {trust_policy_id}"
    (root / "collection.yaml").write_text(
        f"""version: 1
collection:
  id: {collection_id}
  title: Local Notes
  trust_domain: {trust_domain}
notes:
  roots:
{roots_yaml}
  include: [\"*.md\", \"**/*.md\"]
profiles:
  enabled:
{enabled_yaml}
relations:
  vocabulary: core@1
{references}
""",
        encoding="utf-8",
    )
    write_builtin_locks(root, profiles)


def write_builtin_locks(root: Path, enabled_profiles: dict[str, int] | None = None) -> None:
    profiles = enabled_profiles or {}
    profile_lines = "\n".join(
        f'  - identifier: {name}\n    version: {version}\n    sha256: "{BUILTIN_LOCK_DIGESTS.get((name, version), "0" * 64)}"'
        for name, version in profiles.items()
    )
    if not profile_lines:
        profile_lines = "  []"
    vocabulary_digest = BUILTIN_LOCK_DIGESTS[("core@1", 1)]
    (root / "profiles.lock.yaml").write_text(
        f"""version: 1
profiles:
{profile_lines}
relation_vocabularies:
  - identifier: core@1
    version: 1
    sha256: "{vocabulary_digest}"
""",
        encoding="utf-8",
    )


def write_note(
    path: Path,
    *,
    identity: str | None = None,
    body: str = "# Note\n\nBody.\n",
    extra: str = "",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if identity is None:
        path.write_text(body, encoding="utf-8")
        return
    path.write_text(
        f"---\nid: {identity}\ncreated_by: human\n{extra}---\n{body}",
        encoding="utf-8",
    )
