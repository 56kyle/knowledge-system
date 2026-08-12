# Reference

The stable library facade exports:

- `inspect_collection(InspectRequest) -> InspectionReport`
- `validate_collection(ValidateRequest) -> ValidationReport`
- `plan_registration(RegistrationRequest) -> MutationPlan`
- `plan_mutation(MutationRequest) -> MutationPlan`
- `apply_mutation(MutationPlan, ApplyContext) -> ApplyResult`
- `parse_reference(str) -> CanonicalReference`
- `resolve_reference(CanonicalReference, ResolutionContext) -> ResolutionResult`
- `compute_review_basis(bytes) -> ReviewBasis`
- `compute_effective_domains(KnowledgeSnapshot) -> DomainAnalysis`

All public boundary values reject unknown fields and are deeply immutable after validation. JSON reports and plans use schema version `1`.

## Profiles

`flap@1` validates Fleeting captures and review triggers, Literature source versions and terminal item outcomes, Atomic claims and provenance, and Project outcomes, states, and tasks. Deferral remains unresolved work.

`research@1` validates collection-governed kinds, `named` through `applied` maturity, provenance for studied/applied material, discovery edges, maps, and frontiers.

Custom profiles are YAML `ProfileDefinition` documents. They may declare typed fields, enum values, predicates, and the supported `required_together`, `exactly_one`, and `requires` invariants. A profile lock supplies the path and SHA-256 digest. Executable or unknown invariant forms are rejected by the closed schema.

`load_semantic_bundle` is authoritative for profiles and relation vocabulary. The lock file must contain exactly the enabled profiles and selected vocabulary. All custom paths are collection-contained, and identity, version, and raw-byte digest must agree before any semantic consumer proceeds.

## Trust

`authorize` accepts an authenticator-issued `AuthenticatedPrincipal`, a time-bounded `TrustGrant`, an asserted task, an action, exact domains, and an optional collection. The CLI issues a `LocalFilesystemPrincipal` from the current OS account. External authentication remains outside this package.

`compute_effective_domains` follows directed knowledge dependencies to a fixed point. A source node inherits every trust domain of the targets it references. Exact-domain enclaves include only nodes whose complete effective set equals the requested set.

Resolution checks collection authorization before catalog lookup. A denied request does not disclose whether a target exists.

Manifest policy paths are collection-contained. Explicit external policies require an expected ID and canonical digest and cannot disagree with a declared policy. Cross-collection resolution authorizes primary catalog domains before opening, recursively resolves authorized dependencies, computes effective domains through cycles to a fixed point, and then authorizes the complete set. Missing and unauthorized dependencies produce the same unavailable finding. Resolution results attest the participating revisions and effective-domain set.

Recursive relations use the authoritative semantic bundle for instance, predicate, manifest, then required resolution precedence. An unresolved prospective relation is omitted from the effective-domain graph and does not make its containing target unavailable.

## Mutation guarantees

Plans store only collection-relative POSIX target paths, expected hashes, complete proposed bytes, typed identity reservations, decision-input digests, a collection snapshot, and a canonical plan digest. Diff text is review-only and is excluded from authority. Apply recomputes plan integrity, authorization, containment, hashes, parsing, and semantic validation for all results before its first write. Each replacement uses a temporary file in the destination directory and an atomic filesystem replacement. Multi-file crash atomicity is not claimed. A failed rollback raises `ApplyIndeterminateError`.

Apply holds an exclusive `.knowledge-system/collection.lock` from preflight through final write or rollback. Review-tier operations require an in-process `MutationApproval` bound to the authenticated local owner, operation, action, plan digest, snapshot, and policy; explicit-authorization operations additionally require their grant. Unknown stale locks require `--recover-lock` and the same complete owner approval. Plan files are created exclusively and durably; `--stdout` never combines with apply, and register stdout contains only plan JSON.

Automatic same-host dead-PID lock recovery is POSIX-only. Windows cannot reliably prove PID absence with `os.kill(pid, 0)`, so Windows lock recovery requires authenticated owner `--recover-lock` approval.

Retirement ledgers contain typed disposition records. A matching retained retired or superseded tombstone must agree on disposition, canonical note successor, and retirement date; active reuse remains an error. Manifest-declared provenance registries are scheme-specific, reject ambiguous identities, account for every referenced local evidence identity, and record verified, unverifiable, missing, unavailable, and integrity-mismatch states. Local note and block provenance resolve against the indexed collection. Projection ingestion records must agree with their nested revision attestations.
