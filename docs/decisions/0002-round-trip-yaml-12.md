# 0002 - Isolate round-trip YAML 1.2 handling

## Status

Accepted with dependency caution

## Context and problem statement

Canonical notes are human-owned Markdown. Supported metadata changes must preserve comments, order, quoting, line endings, BOM state, and unrelated body bytes. A normalized YAML rewrite creates Git churn and can change YAML 1.1 scalar meaning. Malformed, unterminated, duplicate-key, and non-mapping frontmatter cannot be mutated safely.

## Decision drivers

- Minimal and reviewable Git diffs
- YAML 1.2 scalar behavior
- Duplicate-key and malformed-document rejection
- Exact newline preservation, including CRLF input
- A bounded dependency surface

## Considered options

### `ruamel.yaml` round-trip mode

- Good: retains comments, ordering, quotes, and local style.
- Good: supports YAML 1.2 configuration.
- Bad: exposes mutable dependency-specific node types and has a cautious maturity profile.

### PyYAML safe load and normalized write

- Good: familiar and stable.
- Bad: loses comments and formatting and defaults to YAML 1.1 behavior.

### A custom YAML subset

- Good: would minimize dependencies.
- Bad: cannot safely preserve the YAML already accepted by Obsidian.
- Bad: creates a security-sensitive parser maintenance burden.

## Decision outcome

Use `ruamel.yaml>=0.19.1,<0.20` in round-trip YAML 1.2 mode only behind `codec.py`. Reject duplicate keys, non-mapping frontmatter, malformed YAML, and unterminated delimiters. Preserve the document's detected newline style without converting existing carriage returns twice. Convert dependency-owned values to validated domain values before they cross the codec boundary.

## Consequences

- Supported frontmatter edits retain local authoring choices.
- Unsupported or ambiguous syntax blocks mutation instead of being normalized.
- The upper version bound and isolated codec make a future replacement measurable.
- The scanner remains intentionally bounded and is not a complete CommonMark parser.

## Confirmation

- Round-trip tests cover comments, quote style, order, LF, CRLF, BOM, and body bytes.
- Parser tests block malformed, unterminated, duplicate-key, and non-mapping frontmatter.
- Read-only commands preserve bytes and modification times.

## References

- YAML 1.2 specification
- `ruamel.yaml` round-trip documentation
- `src/knowledge_system/codec.py`
