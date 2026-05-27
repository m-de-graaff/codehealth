# codehealth

`codehealth` is a local-first CLI for finding duplicated logic, risky structural repetition, framework-specific health issues, and safe opportunities to simplify code.

The current repository is the Phase 0/1 bootstrap. It defines the product scope and creates a Rust workspace with a working CLI pipeline. Detector rules are intentionally not implemented yet.

## Current CLI

```powershell
cargo run -p codehealth-cli -- --version
cargo run -p codehealth-cli -- scan .
cargo run -p codehealth-cli -- scan fixtures --format json
cargo run -p codehealth-cli -- scan fixtures --format markdown
cargo run -p codehealth-cli -- dupes fixtures/duplicates --color always
cargo run -p codehealth-cli -- rules
cargo run -p codehealth-cli -- explain duplicate.exact_file
```

`scan` and `dupes` currently implement one shallow detector: `duplicate.exact_file`, which groups supported source files with identical whitespace-normalized contents. Deeper structural, semantic, React, FastAPI, and Rust-specific rules are listed in the rule catalog but are not implemented yet.

Use `cargo install --path crates/cli` if you want `codehealth` available directly on your `PATH`.

## Common commands

```powershell
codehealth
codehealth init
codehealth config validate
codehealth scan . --format text --color auto
codehealth scan . --format json --output codehealth.json
codehealth scan . --format sarif --output codehealth.sarif
codehealth scan . --format markdown --output codehealth.md
codehealth scan . --format html --output codehealth.html
codehealth scan . --write-baseline .codehealth/baseline.json
codehealth ci . --baseline .codehealth/baseline.json --fail-on new-high
codehealth scan . --fail-on high
codehealth scan . --no-score
codehealth dupes . --min-confidence high
codehealth scan . --show-suppressed
codehealth rules
codehealth explain duplicate.exact.file
```

`codehealth.toml` is discovered from the current directory upward, or explicitly with `--config`.
Rule IDs are reported in canonical dotted form, for example `duplicate.exact.file`; older aliases such as `duplicate.exact_file` are still accepted in config, suppressions, and `explain`.
Reports include a deterministic v1 health score with category scores, top contributors, and summary metrics. See `docs/scoring.md` for the score model and disable options.
`--format json` uses the public `schemaVersion: "1.0.0"` report schema with tool version, config hash, metrics, timing, findings, and score data. SARIF targets GitHub code scanning, Markdown is suitable for PR comments, and HTML is a single-file local report. See `docs/reporting.md` for schema details.

Existing codebases can adopt CI without fixing every current finding:

```powershell
codehealth scan . --write-baseline .codehealth/baseline.json
codehealth ci . --fail-on new-high
```

The baseline records stable fingerprints, related duplicate locations, first-seen timestamps, and optional ownership. CI allows existing findings and fails on new findings at the configured threshold. Use `--update-baseline` to intentionally accept the current state after reviewing changes.

Inline suppressions are supported:

```ts
// codehealth-ignore-next-line duplicate.exact.file -- intentional generated copy
export function generatedAdapter() {}

// codehealth-ignore-start duplicate.exact.file -- compatibility layer
export function legacyAdapter() {}
// codehealth-ignore-end duplicate.exact.file
```

Suppressed findings are hidden by default and counted in the summary. Use `--show-suppressed` to include them in text/JSON/SARIF/HTML reports.

Hidden debug commands are available for development:

```powershell
codehealth debug parse fixtures/rust/lib.rs
codehealth debug ast fixtures/rust/lib.rs
codehealth debug fingerprints fixtures/duplicates/a.ts
codehealth debug symbols fixtures/rust/lib.rs
```

## Supported v1 targets

- TypeScript and TSX
- Python
- Rust
- React framework rules
- FastAPI framework rules

## Development

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

See `docs/` for product scope, finding taxonomy, severity/confidence policy, and autofix policy.
