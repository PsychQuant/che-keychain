## 1. Policy and preparation

- [x] 1.1 Deliver Explicit replacement policy through set --replace while preserving default refusal; verify parser and default-policy tests.
- [x] 1.2 Deliver Backup and identity checks before deletion; verify unreadable-backup and nonsecret-rehearsal refusal leave the original item unchanged.

## 2. Replacement and recovery

- [x] 2.1 Deliver Recovery with original access after add or read-back failure; verify original bytes and allow-all ACL survive injected failures.
- [x] 2.2 Deliver Safe failure handling and Outcome reporting; verify unavailable read-back is left alone and failed recovery is not reported as restored.
- [x] 2.3 Preserve the Noninteractive access boundary; verify stdin refuses widening a non-allow-all item and allows backed-up allow-all rotation.

## 3. Documentation and verification

- [x] 3.1 Publish Honest guarantees and the migration prerequisites in help/README; review actual CLI help and output for no secret disclosure.
- [x] 3.2 Run the complete tests and spectra validate; confirm all requirements and design decisions above have passing evidence.
