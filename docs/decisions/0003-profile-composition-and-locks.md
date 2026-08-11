# 0003 - Compose explicit, integrity-locked profiles

## Status

Accepted

## Context and problem statement

FLAP lifecycle, research maturity, domain kind, and structural relations describe independent dimensions. A universal taxonomy would conflate them. Agents also need to know the exact profile and predicate contracts used by a collection; a name alone can change meaning over time.

## Decision drivers

- Optional FLAP participation
- Compatible simultaneous research and lifecycle semantics
- Reproducible interpretation for humans and agents
- Extensibility without executable collection code
- Unambiguous ownership of fields and predicates

## Considered options

### One universal taxonomy

- Good: simple selection and validation.
- Bad: conflates lifecycle, epistemic maturity, note role, and domain kind.

### Independent systems connected by adapters

- Good: preserves each existing model unchanged.
- Bad: creates semantic translation loss and duplicate identity envelopes.

### Shared envelope with composable locked profiles

- Good: keeps identity, provenance, and review common while dimensions remain independent.
- Good: integrity locks make interpretation reproducible.
- Bad: requires composition and ownership validation.

## Decision outcome

Use one progressive base envelope and explicit `name@version` profile references. Package `flap@1` and `research@1`. Bind every enabled profile and relation vocabulary to an identifier, version, SHA-256 digest, and optional contained definition path. Custom profiles are declarative: they own only fields under a declared prefix, cannot claim base or built-in fields, cannot duplicate predicate ownership, and may use only implemented invariant forms. Every declared invariant executes. `requires` has an ordered source plus at least one dependency.

`load_semantic_bundle` is the only semantic loading boundary. It requires exactly one lock for every enabled profile and the selected vocabulary, rejects unselected or duplicate locks, verifies built-in digests, and verifies every custom definition's contained path, raw-byte digest, identity, and version. Validation, registration, relation interpretation, mutation snapshots, and apply revalidation consume this same bundle; no subsystem may reinterpret lock files independently.

FLAP keeps Fleeting, Literature, Atomic, and Project as lifecycle classes. Deferred Literature remains unchecked and has a date or event trigger; processed Literature has only terminal items. Project states and terminal states are collection settings. Research keeps fixed maturity ordering, collection-governed kinds, map/frontier roles, and governed `led_to` relations. Structural `up` is common, singular, non-self, acyclic, canonical, and resolvable.

## Consequences

- Notes can carry multiple independent profiles without losing portable Markdown behavior.
- Collection owners must update locks deliberately when semantics change.
- Executable custom invariants remain excluded.
- Conflicting ownership or a bad lock blocks validation.

## Confirmation

- Validation covers dual-profile notes, state transitions, research maturity, ownership conflicts, predicate conflicts, digest mismatch, and every invariant form.
- Schema export exposes the complete built-in contracts.
- Unknown or conflicting definitions fail closed.
- Tests prove that extra, missing, duplicate, mismatched, and escaping locks fail identically at every consuming boundary.

## References

- `src/knowledge_system/profiles.py`
- `src/knowledge_system/validation.py`
- `profiles.lock.yaml` schema
