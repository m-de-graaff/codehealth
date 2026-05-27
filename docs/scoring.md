# Code Health Scoring

The health score is a deterministic v1 signal, not a mathematical proof of code quality.

## Model

- Base score: `100`.
- Severity points: `info=0`, `low=1`, `medium=3`, `high=8`, `critical=15`.
- Confidence multipliers: `low=25%`, `medium=50%`, `high=80%`, `certain=100%`.
- Generated files included with `scanner.include_generated = true` use a `25%` context multiplier.
- Test and fixture paths use a `50%` context multiplier.
- Suppressed findings do not affect score.
- Repeated identical findings are capped: first full penalty, findings 2-3 half penalty, findings 4-10 quarter penalty, later repeats zero, capped at three times the largest single penalty.

Scores are reported globally and by category. Category scores are independent views, so one finding can contribute to more than one category.

## Disabling

Disable scoring for one run:

```powershell
codehealth scan . --no-score
```

Disable scoring in config:

```toml
[scoring]
enabled = false
```
