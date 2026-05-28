# Embedding Privacy

Vector candidate discovery is optional. The default configuration keeps embeddings disabled and does not make network calls.

## Defaults

- `[embeddings] enabled = false` means no function summaries are embedded.
- `provider = "none"` is the only production provider in this version.
- `provider = "local"` and `provider = "external"` are reserved for future versions and are rejected by config validation.
- `privacy_mode = "disabled"` is the default. `local_only` and `external_opt_in` are accepted policy labels, but no external provider exists in this version.

## Summary Inputs

When embeddings are enabled, codehealth builds compact function summaries instead of embedding full source. Summaries include names, signatures, canonical AST metrics, calls, coarse reads/writes, return shape, framework tags, and short nearby doc comments when useful.

Summaries redact secret-like text, strip long literals, and skip generated files. Generated files use the same detection path as workspace scanning.

## Cache

Vector cache files live under the active cache directory, defaulting to `.codehealth/cache/vectors`.

Cache writes are disabled when:

- `--no-cache` is passed.
- `[cache] enabled = false`.
- `[embeddings] cache_vectors = false`.
- The provider returns an empty vector, as the no-op provider does.

Cache keys include the provider id, summary version, privacy mode, summary hash, and symbol identity. Cache entries do not store full source.
