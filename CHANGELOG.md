# Changelog

## Unreleased

- Add Phase 2 CLI command surface: `scan`, `dupes`, `rules`, `init`, `config validate`, `explain`, and hidden debug commands.
- Add text, JSON, SARIF, and standalone HTML report rendering.
- Add colored severity output with `--color auto|always|never`.
- Add severity, confidence, language, framework, CI, cache, and autofix flags.
- Add shallow `duplicate.exact_file` detector for exact whitespace-normalized whole-file duplicates.
- Add stable report schema with stats, score, multi-location findings, explanations, remediation, and baseline keys.

## 0.1.0

- Bootstrap Rust workspace and CLI shell.
- Add Phase 0 product documentation.
- Add file discovery, config, parser registry, reporter, and test scaffolding.
