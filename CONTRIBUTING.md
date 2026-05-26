# Contributing

## Local checks

Run the same checks as CI before opening changes:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional local hook:

```powershell
git config core.hooksPath .githooks
```

## Rule changes

Rules should include fixtures for true positives and false positives. A rule that can block CI needs an explicit severity, confidence, and false-positive rationale in tests or docs.

## False positives

False positives are product bugs. Prefer reducing confidence or making a rule opt-in over shipping noisy defaults.
