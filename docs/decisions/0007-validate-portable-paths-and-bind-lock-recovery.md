# 0007 - Validate portable paths and bind lock recovery

## Status

Accepted

## Context and problem statement

Mutation plans store collection-relative paths and collection locks as portable wire data. Native `Path` parsing gives the same path different drive semantics on Windows and POSIX. Collection-lock recovery also read an untyped JSON mapping and later unlinked the path without proving that it still named the file whose ownership was evaluated.

Portable Python does not provide an atomic unlink-if-file-identity-and-content-match operation. On Windows, retaining an open file handle can also prevent deletion unless every participant uses compatible sharing flags.

## Decision drivers

- One path grammar on every supported operating system
- Early rejection of invalid hostile wire values
- Typed immutable lock ownership facts
- Automatic recovery only for a provably stale, dead, same-host POSIX owner
- Explicit owner-approved recovery for malformed, unknown, and Windows locks
- Recovery and release bound to the lock that was inspected
- No new runtime dependency or public API

## Considered options

### Continue using native `Path` classification

- Good: delegates syntax to the host filesystem library.
- Bad: accepts Windows drive-qualified wire paths on POSIX and makes saved-plan validation host-dependent.

### Use `PurePosixPath` plus `PureWindowsPath`

- Good: exposes both standard path models.
- Bad: still requires additional checks for the deliberately normalized wire grammar and obscures the small accepted syntax.

### Validate wire segments before creating a native path

- Good: defines one explicit portable grammar and creates native paths only from validated segments.
- Bad: the application owns this small grammar.

### Keep lock records as untyped mappings

- Good: minimal code.
- Bad: permits invalid JSON shapes, boolean integers, invalid process facts, and fixture drift.

### Retain an open lock handle through conditional deletion

- Good: stronger identity binding on POSIX systems with handle-relative unlink support.
- Bad: Python has no portable handle-relative conditional unlink, and ordinary Windows handles can prevent deletion.

### Reinspect identity, bytes, and nonce immediately before unlink

- Good: portable, testable, and detects replacement before the final removal attempt.
- Bad: a residual race remains between the final inspection and pathname unlink.

## Decision outcome

Validate mutation path strings before native materialization. Reject empty values, NUL, leading slash or backslash, an ASCII drive designator at the start of any normalized segment, and empty, dot, or dot-dot segments. Normalize accepted backslashes to POSIX separators for compatibility, then create a native `Path` from the validated segments. Colons that do not form a per-segment drive designator remain valid wire characters.

Represent collection-lock data with a private frozen record. Encode exactly `created`, `host`, `nonce`, and `pid` as canonical JSON. Decode only an object with those exact fields and validated types: a positive non-boolean PID representable as a signed 32-bit process identifier, a null or normalized host, a finite nonnegative representable creation time, and a 32-character lowercase hexadecimal nonce. Treat every other readable byte sequence as unknown ownership. Unknown ownership fails closed unless recovery is requested by the current local principal with a complete in-process approval bound to the operation. A process identifier that the local OS cannot represent is unverifiable and is never considered dead.

Inspect lock files through an open regular-file handle and retain their device, inode, exact bytes, and validated record when present. Immediately before recovery or release, reopen the pathname and require the same device/inode and bytes; when a record is valid, also require the expected nonce. Any mismatch or unverifiable filesystem operation fails recovery closed. Release remains best-effort and leaves a changed lock in place.

The last comparison and pathname unlink cannot be one portable atomic operation. The residual race is accepted under ADR 0005's existing assumption that collection ACLs prevent an untrusted principal from replacing collection-owned state. Cooperating writers are detected by exclusive creation and the immediate identity/content/nonce recheck; stronger adversarial guarantees require platform-specific directory-handle APIs outside the portable contract.

## Consequences

- The same serialized mutation path is accepted or rejected on Windows, macOS, and Linux.
- Valid lock records have one construction and serialization boundary usable by production and ordinary test fixtures.
- Malformed JSON cannot leak attribute or numeric-shape errors into recovery.
- Replacing or rewriting a lock between ownership evaluation and the final recheck prevents removal.
- Collection ACL integrity remains a documented prerequisite for the final pathname operation.

## Confirmation

- Exercise portable path syntax directly, including Windows drive-relative and drive-absolute forms on POSIX.
- Round-trip valid lock records and reject every invalid field type and shape.
- Verify malformed locks require complete approved recovery.
- Replace lock bytes or filesystem identity between inspection and removal and verify fail-closed behavior.
- Run mutation and collection-lock integration tests on Windows and POSIX CI workers.

## References

- `src/knowledge_system/mutation.py`
- ADR 0005 for mutation-plan hostility, lock policy, and collection ACL assumptions
