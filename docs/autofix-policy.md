# Autofix Policy

## Safety levels

- `unavailable`: no automated edit is offered.
- `suggestion_only`: the report can describe a possible edit, but the tool must not apply it automatically.
- `safe`: the edit is local, formatting-preserving enough for review, and covered by targeted tests.

## Allowed v1 autofix candidates

- Boolean return simplifications.
- Trivial branch removal.
- Expression-bodied arrow conversions when TypeScript syntax is unambiguous.

## Not allowed in v1

- Cross-file refactors.
- Public API renames.
- Semantic duplicate consolidation.
- Framework rewrites that change data flow, hook ordering, dependency injection, or async behavior.
