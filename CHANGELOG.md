# Changelog

## [0.2.0] - 2026-05-06

### Added
- Core threat classification engine with multi-factor scoring
- `ThreatReport`, `AssetExposure`, `ClassificationResult` models
- Scorer with source reliability (A-F), corroboration, time sensitivity, asset exposure factors
- Severity thresholds: Critical ≥80, High ≥60, Medium ≥40, Low <40
- CLI (`classify`) accepting JSON file path or stdin, returning JSON output
- 47 unit tests covering all scoring logic, CLI I/O, edge cases, and boundary conditions
- GitHub Actions CI workflow (ruff + pyright + pytest)

Closes #4, #5, #6
