# Reporting Formats

`codehealth scan` supports `text`, `json`, `sarif`, `html`, and `markdown` report formats.

## JSON Schema

`--format json` emits the public report schema, not the internal Rust `ScanResult` model.

```json
{
  "schemaVersion": "1.0.0",
  "toolVersion": "0.1.0",
  "configHash": "sha256-of-effective-config",
  "workspaceRoot": "/repo",
  "filesScanned": 0,
  "score": {
    "enabled": true,
    "overall": 100,
    "categories": {}
  },
  "findings": [],
  "metrics": {},
  "timing": {
    "scanMs": 0,
    "reportMs": 0,
    "totalMs": 0
  }
}
```

Top-level fields:

- `schemaVersion`: JSON report schema version. Current version is `1.0.0`.
- `toolVersion`: CLI package version that produced the report.
- `configHash`: SHA-256 of the effective config after defaults and normalization.
- `workspaceRoot`: absolute scan root used for relative report paths.
- `filesScanned`: convenience copy of `metrics.filesScanned`.
- `score`: global score, category scores, top contributors, and score model details.
- `findings`: stable finding records with `ruleId`, `baselineKey`, severity, confidence, locations, remediation, suppression data, metadata, and duplicate related locations.
- `metrics`: scan counts, summary metrics, duplicate metrics, largest definitions, suppressed rules, and baseline comparison status.
- `timing`: scan, report, and total elapsed milliseconds.

Finding locations use relative paths when possible and include line/column, byte span, language, and best-effort source snippets. Duplicate findings include `relatedLocations` and `duplicateGroup` when the detector can identify related source locations.

Findings include `baselineStatus` when a baseline is checked. Values are `new`, `existing`, `changed`, or `not_checked`. Fixed baseline entries are reported under `metrics.baseline.fixed`.

Baseline files may be produced with `codehealth scan . --write-baseline .codehealth/baseline.json`. The reader accepts the current baseline schema, Phase 10 JSON reports, and the previous internal `baseline_key` field.

## Baseline And CI

Create a baseline before enabling CI in an existing repository:

```powershell
codehealth scan . --write-baseline .codehealth/baseline.json
codehealth ci . --fail-on new-high
```

Baseline entries store stable fingerprints, rule IDs, paths, normalized source context hashes, duplicate related locations, first-seen timestamps, and optional owners. Set ownership with `--baseline-owner <team>` or `[ci] baseline_owner = "team"` in config.

Use `--update-baseline` with `--baseline` after review to intentionally accept the current state. `--write-baseline` refuses to overwrite an existing file unless `--force-baseline` is supplied.

`codehealth ci` uses `ci.fail_on` from config. If no threshold is configured, it defaults to `new-high`, so existing findings pass and newly introduced high-severity findings fail.

## SARIF

`--format sarif` emits SARIF `2.1.0` for GitHub code scanning:

- Rule IDs are mapped into `runs[0].tool.driver.rules`.
- Severity maps to SARIF levels: high/critical to `error`, medium to `warning`, low/info to `note`.
- Primary findings use precise `physicalLocation.region` spans where available.
- Duplicate locations are emitted as `relatedLocations`.
- `partialFingerprints["codehealth/baselineKey"]` carries the stable baseline key.
- Rule help text is populated from the rule catalog.

## Markdown

`--format markdown` emits a concise PR-comment summary. When a baseline comparison is available, it includes only new findings by default. Lower-severity findings are collapsed in a `<details>` section.

## HTML

`--format html` emits a single-file report with inline CSS and JavaScript. The MVP includes score overview, filters, snippets, and duplicate group viewing without requiring a server or external assets.
