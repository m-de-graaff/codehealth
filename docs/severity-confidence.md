# Severity and Confidence Policy

## Severity

- `info`: useful context, never blocks CI.
- `low`: maintainability issue, usually advisory.
- `medium`: repeated pattern or framework issue worth fixing.
- `high`: likely bug, risky duplication, or rule violation.
- `critical`: severe correctness or safety issue.

## Confidence

- `certain`: deterministic evidence, such as exact normalized duplicate bodies.
- `high`: strong structural evidence with low expected false-positive rate.
- `medium`: credible signals that need review.
- `low`: weak signal or exploratory finding.

## CI behavior

Default CI behavior should block only on new `high` or `critical` findings with `high` or `certain` confidence. Baseline mode compares against a committed report and fails only for new blocking findings.

## False-positive policy

False positives are treated as product defects. A noisy rule should be lowered in confidence, gated by configuration, or disabled by default until fixtures demonstrate acceptable precision.
