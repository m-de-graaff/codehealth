# V1 Product Scope

## Product shape

`codehealth` is a CLI-first static analysis tool with CI/reporting support. The v1 implementation is local-first and does not require a hosted service.

Planned extension points:

- GitHub Action wrapper.
- HTML report output.
- VS Code extension.
- Hosted dashboard.

## Initial languages

- TypeScript.
- TSX.
- Python.
- Rust.

## Initial frameworks

- React.
- FastAPI.

## Core promise

Find duplicated logic, risky structural repetition, framework-specific health issues, and safe opportunities to simplify code.

## Non-goals for v1

- Full theorem-proving semantic equivalence.
- Fully automatic large-scale refactors.
- Native dependency vulnerability database.
- Replacement for ESLint, Ruff, Clippy, or the TypeScript compiler.

## Implementation scope for the bootstrap slice

The first implementation creates the workspace, CLI, shared data model, config loading, file discovery, reporter shells, and parser registry. It does not implement detector logic.
