# Findings Taxonomy

## Duplicate findings

- `DuplicateNameFinding`: duplicate function, class, method, React component, FastAPI route, or Rust trait/impl method names in similar contexts.
- `ExactDuplicateFinding`: same normalized source body, including matches after comment and whitespace removal.
- `StructuralDuplicateFinding`: same normalized AST, alpha-renamed identifiers, or same control-flow shape.
- `NearDuplicateFinding`: high AST/token shingle overlap, similar call graph, or small structural edits.
- `SemanticCandidateFinding`: similar behavior according to multiple weak signals. These are never guaranteed equivalent and require manual review.

## General style findings

- Boolean return simplification.
- Expression-bodied arrow opportunity.
- Unnecessary branches.
- Large function.
- High complexity.

## React findings

- Large component.
- Duplicate component structure.
- Suspicious hook usage.
- Unnecessary `useEffect`.
- Prop drilling.
- Unstable list keys.

## FastAPI findings

- Duplicate routes.
- Blocking call inside `async def`.
- Route handler doing too much business logic.
- Repeated dependency/auth logic.
- Missing `response_model`.

## Rust findings

- Duplicate impl methods.
- Repeated `match`/`Result` handling.
- Large functions.
- Unsafe `unwrap`/`expect` policy violation.
- Manual patterns better handled by idiomatic combinators.
