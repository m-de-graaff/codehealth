# codehealth

`codehealth` is a local-first CLI for finding duplicated logic, risky structural repetition, framework-specific health issues, and safe opportunities to simplify code.

The current repository is the Phase 0/1 bootstrap. It defines the product scope and creates a Rust workspace with a working CLI pipeline. Detector rules are intentionally not implemented yet.

## Current CLI

```powershell
cargo run -p codehealth-cli -- --version
cargo run -p codehealth-cli -- scan .
cargo run -p codehealth-cli -- scan fixtures --format json
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
codehealth scan . --format sarif --output codehealth.sarif
codehealth scan . --fail-on high
codehealth dupes . --min-confidence high
codehealth rules
codehealth explain duplicate.exact_file
```

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
