# codehealth

`codehealth` is a local-first CLI for finding duplicated logic, risky structural repetition, framework-specific health issues, and safe opportunities to simplify code.

The current repository is the Phase 0/1 bootstrap. It defines the product scope and creates a Rust workspace with a working CLI pipeline. Detector rules are intentionally not implemented yet.

## Current CLI

```powershell
cargo run -p codehealth-cli -- --version
cargo run -p codehealth-cli -- scan .
cargo run -p codehealth-cli -- scan fixtures --format json
```

`scan` discovers supported files and returns a zero-finding report until detector crates are implemented.

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
