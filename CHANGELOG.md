# Changelog

## Unreleased

## 0.2.0 - 2026-05-27

- Add TOML configuration system with parent-directory discovery and explicit `--config`.
- Add full default `codehealth.toml` generation through `codehealth init`.
- Add config validation for unknown rule IDs, invalid rule levels, invalid enum values, and invalid glob patterns.
- Add canonical rule IDs with backwards-compatible aliases.
- Add project language filtering, ignored paths, rule severity overrides, rule include/exclude paths, and path overrides.
- Add inline next-line and block suppressions plus `--show-suppressed`.
- Add CLI command surface: `scan`, `dupes`, `rules`, `init`, `config validate`, `explain`, and hidden debug commands.
- Add text, stable JSON, SARIF, standalone HTML, and Markdown report rendering.
- Add colored severity output with `--color auto|always|never`.
- Add severity, confidence, language, framework, CI, cache, and autofix flags.
- Add shallow `duplicate.exact_file` detector for exact whitespace-normalized whole-file duplicates.
- Add stable report schema with stats, score, multi-location findings, explanations, remediation, and baseline keys.
- Add schema v2 structured health scoring with category scores, top contributors, summary metrics, baseline comparison counts, and `--no-score`.
- Add public JSON report schema `1.0.0`, report timing/config hash metadata, GitHub-oriented SARIF related locations, and PR-comment Markdown summaries.
- Add baseline creation, intentional baseline updates, per-finding baseline status, fixed finding reporting, and `codehealth ci --fail-on new-high`.
- Add style rule engine foundations with safe autofix plumbing and TypeScript, Python, and Rust style checks.
- Add React project/component modeling, duplicate JSX detection, and React maintainability rules.
- Add FastAPI route/model indexing, duplicate/conflicting route checks, async blocking-call checks, and conservative Pydantic duplication suggestions.
- Add Rust function, impl, trait implementation, macro, unsafe, and panicking-call analysis with Rust health rules.
- Add optional Cargo Clippy integration that merges and de-duplicates Clippy findings when requested.

## 0.1.0

- Bootstrap Rust workspace and CLI shell.
- Add product documentation.
- Add file discovery, config, parser registry, reporter, and test scaffolding.
