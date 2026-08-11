# Usage

## Inspect and validate

```console
kn inspect PATH --format text
kn validate PATH --format json
```

Inspection discovers root-level and nested Markdown without changing bytes or timestamps. Validation adds identity, profile, relation, provenance, structural-cycle, and lock checks. Generic collections without `collection.yaml` remain valid portable Markdown collections.

Exit code `0` means success without blocking findings. Code `1` means validation errors or critical findings. Code `2` means invalid invocation, configuration, authorization, or environment. Code `3` means a compare-and-swap conflict with no writes. Code `4` means apply or rollback became indeterminate and requires recovery.

## Register a note

Registration is preview-first:

```console
kn register notes/discovery.md \
  --collection . \
  --actor agent:codex \
  --task task:research-42 \
  --profile research@1 \
  --origin agent \
  --plan-out registration.json
```

Add `--apply` only after reviewing the plan and diff. CLI registration defaults conservatively to `origin: agent` and `unreviewed`; `--origin` makes the input explicit. The CLI authenticates the current OS account for its local filesystem boundary but does not authenticate the asserted actor. Library callers use an authenticator-issued principal at apply.

With `--stdout`, register writes only the plan JSON to standard output. Any human-readable diff is written to standard error so the JSON stream remains machine-readable.

## Other mutations

`kn mutation plan request.json --out plan.json` accepts the versioned `MutationRequest` schema with an intent-specific typed payload. Supported intents are create, register, set or remove `tags` or `aliases`, replace one selected `tags` or `aliases` subtree, identity-preserving move, reserve a collection ID in a catalog, and atomically mark an active note retired while appending its ID to the retirement ledger.

Deletion, merge, supersession, publication, declassification, and arbitrary byte replacement are intentionally unavailable.

## Review and impact

```console
kn review basis notes/claim.md
kn impact note:architecture/stable-identities --collection .
```

Review bases normalize line endings and exclude review-attestation metadata. Moving a note does not change its basis. Material content changes do.

## Schemas

```console
kn schema export --destination schemas
kn schema export --destination schemas --check
```

Pydantic models are authoritative. The committed JSON Schemas are deterministic projections and must not drift.
