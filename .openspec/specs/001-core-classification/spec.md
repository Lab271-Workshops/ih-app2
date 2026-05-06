# Spec 001: Core Classification

**Epic:** #1 Phase 1 — Core Classification
**Status:** Draft
**Stories:** #4, #5, #6

## Overview

The Threat Classifier accepts cyber threat reports as JSON and returns a severity classification (Critical/High/Medium/Low) with a numeric score and per-factor breakdown. This enables Security Analysts to triage incoming threat intelligence and prioritize response.

## Domain Model

```
ThreatReport
├── id: string
├── title: string
├── description: string
├── source: Source
│   ├── name: string
│   └── reliability: A | B | C | D | E | F
├── corroboration: Corroboration[]
│   ├── source: string
│   └── date: ISO8601
├── time_sensitivity: TimeSensitivity
│   ├── active_exploitation: boolean
│   └── days_until_critical: integer
├── asset_exposure: AssetExposure
│   ├── affected_systems: string[]
│   ├── data_classification: public | internal | confidential | secret
│   └── internet_facing: boolean
└── created: ISO8601

ClassificationResult
├── id: string (from input)
├── severity: CRITICAL | HIGH | MEDIUM | LOW
├── score: integer (0-100)
├── breakdown: ScoreBreakdown
│   ├── source_reliability: integer (0-25)
│   ├── corroboration: integer (0-20)
│   ├── time_sensitivity: integer (0-25)
│   └── asset_exposure: integer (0-25)
└── rationale: string
```

---

## Requirements

### Requirement 1: JSON Input Format [MUST]

The system MUST accept threat reports as JSON documents conforming to the ThreatReport schema.

**Implementation:** `src/threat_classifier/models.py::ThreatReport`

#### Scenario: Valid report accepted

- GIVEN a JSON file containing all required fields
- WHEN the classifier processes the file
- THEN it returns a ClassificationResult

**Tests:** `tests/test_classifier.py::TestInput::test_valid_report_accepted`

#### Scenario: Invalid report rejected

- GIVEN a JSON file missing required fields
- WHEN the classifier processes the file
- THEN it returns an error with field name

**Tests:** `tests/test_classifier.py::TestInput::test_invalid_report_rejected`

---

### Requirement 2: Source Reliability Scoring [MUST]

The system MUST score source reliability using NATO-style ratings (A-F) mapped to points.

| Rating | Description | Points |
|--------|-------------|--------|
| A | Completely reliable | 25 |
| B | Usually reliable | 20 |
| C | Fairly reliable | 15 |
| D | Not usually reliable | 10 |
| E | Unreliable | 5 |
| F | Reliability unknown | 0 |

**Implementation:** `src/threat_classifier/classifier.py::score_source_reliability`

#### Scenario: Source rated A

- GIVEN a report with source reliability "A"
- WHEN scored
- THEN source_reliability = 25

**Tests:** `tests/test_classifier.py::TestScoring::test_source_reliability_a`

#### Scenario: Unknown source defaults to F

- GIVEN a report with no reliability rating
- WHEN scored
- THEN source_reliability = 0

**Tests:** `tests/test_classifier.py::TestScoring::test_source_reliability_default`

---

### Requirement 3: Corroboration Scoring [MUST]

The system MUST score corroboration based on independent confirming sources.

- 10 points per independent source
- Maximum 20 points (cap at 2 sources)

**Implementation:** `src/threat_classifier/classifier.py::score_corroboration`

#### Scenario: Two corroborating sources

- GIVEN a report with 2 corroborating sources
- WHEN scored
- THEN corroboration = 20

**Tests:** `tests/test_classifier.py::TestScoring::test_corroboration_two_sources`

#### Scenario: No corroboration

- GIVEN a report with empty corroboration list
- WHEN scored
- THEN corroboration = 0

**Tests:** `tests/test_classifier.py::TestScoring::test_corroboration_none`

---

### Requirement 4: Time Sensitivity Scoring [MUST]

The system MUST score time sensitivity based on exploitation status and urgency.

| Condition | Points |
|-----------|--------|
| Active exploitation | 25 |
| < 7 days until critical | 20 |
| < 30 days until critical | 15 |
| Otherwise | 10 |

**Implementation:** `src/threat_classifier/classifier.py::score_time_sensitivity`

#### Scenario: Active exploitation

- GIVEN a report with active_exploitation = true
- WHEN scored
- THEN time_sensitivity = 25

**Tests:** `tests/test_classifier.py::TestScoring::test_time_active_exploitation`

#### Scenario: 14 days until critical

- GIVEN a report with days_until_critical = 14
- WHEN scored
- THEN time_sensitivity = 15

**Tests:** `tests/test_classifier.py::TestScoring::test_time_14_days`

---

### Requirement 5: Asset Exposure Scoring [MUST]

The system MUST score asset exposure based on exposure factors.

| Factor | Points |
|--------|--------|
| Internet-facing | +10 |
| Data classification confidential/secret | +10 |
| Per affected system | +5 (cap at 25 total) |

**Implementation:** `src/threat_classifier/classifier.py::score_asset_exposure`

#### Scenario: Internet-facing confidential system

- GIVEN a report with internet_facing=true, data_classification="confidential", 1 system
- WHEN scored
- THEN asset_exposure = 25 (10+10+5)

**Tests:** `tests/test_classifier.py::TestScoring::test_asset_exposure_internet_confidential`

#### Scenario: Internal public system

- GIVEN a report with internet_facing=false, data_classification="public", 1 system
- WHEN scored
- THEN asset_exposure = 5

**Tests:** `tests/test_classifier.py::TestScoring::test_asset_exposure_internal_public`

---

### Requirement 6: Severity Classification [MUST]

The system MUST classify severity based on total score thresholds.

| Score Range | Severity |
|-------------|----------|
| >= 80 | CRITICAL |
| >= 60 | HIGH |
| >= 40 | MEDIUM |
| < 40 | LOW |

**Implementation:** `src/threat_classifier/classifier.py::classify_severity`

#### Scenario: Score 92 is Critical

- GIVEN a total score of 92
- WHEN classified
- THEN severity = CRITICAL

**Tests:** `tests/test_classifier.py::TestClassification::test_critical_threshold`

#### Scenario: Score 60 is High

- GIVEN a total score of 60
- WHEN classified
- THEN severity = HIGH

**Tests:** `tests/test_classifier.py::TestClassification::test_high_threshold`

---

### Requirement 7: Score Breakdown [MUST]

The system MUST return a breakdown showing points per scoring factor.

**Implementation:** `src/threat_classifier/classifier.py::Classifier.classify`

#### Scenario: Breakdown sums to total

- GIVEN any valid report
- WHEN classified
- THEN sum(breakdown values) = score

**Tests:** `tests/test_classifier.py::TestClassification::test_breakdown_sums_to_total`

---

### Requirement 8: Human Rationale [SHOULD]

The system SHOULD return a human-readable rationale explaining the classification.

**Implementation:** `src/threat_classifier/classifier.py::generate_rationale`

#### Scenario: Rationale includes key factors

- GIVEN a Critical classification
- WHEN rationale generated
- THEN rationale mentions source rating, corroboration count, time status, and exposure

**Tests:** `tests/test_classifier.py::TestClassification::test_rationale_content`

---

### Requirement 9: CLI Interface [MUST]

The system MUST provide a command-line interface for classification.

```bash
# File input
classify report.json

# Stdin input
cat report.json | classify -
```

**Implementation:** `src/threat_classifier/cli.py::main`

#### Scenario: Classify file

- GIVEN a valid JSON file at path `report.json`
- WHEN `classify report.json` executed
- THEN stdout contains ClassificationResult as JSON

**Tests:** `tests/test_cli.py::TestCLI::test_classify_file`

#### Scenario: Classify stdin

- GIVEN valid JSON piped to stdin
- WHEN `classify -` executed
- THEN stdout contains ClassificationResult as JSON

**Tests:** `tests/test_cli.py::TestCLI::test_classify_stdin`

---

### Requirement 10: JSON Output [MUST]

The system MUST output valid JSON to stdout.

**Implementation:** `src/threat_classifier/cli.py::output_result`

#### Scenario: Success output

- GIVEN a successful classification
- WHEN output
- THEN stdout is valid JSON with severity, score, breakdown, rationale

**Tests:** `tests/test_cli.py::TestCLI::test_output_valid_json`

#### Scenario: Error output

- GIVEN a classification error
- WHEN output
- THEN stdout is JSON `{"error": "<message>"}` and exit code != 0

**Tests:** `tests/test_cli.py::TestCLI::test_error_output`

---

## Example

**Input:**
```json
{
  "id": "TR-2026-0512",
  "title": "Active exploitation of CVE-2026-1234",
  "description": "APT-29 exploiting Apache Struts RCE",
  "source": {"name": "Mandiant", "reliability": "A"},
  "corroboration": [
    {"source": "CISA KEV", "date": "2026-05-05"},
    {"source": "CrowdStrike", "date": "2026-05-04"}
  ],
  "time_sensitivity": {"active_exploitation": true, "days_until_critical": 2},
  "asset_exposure": {
    "affected_systems": ["web-prod-01", "web-prod-02"],
    "data_classification": "confidential",
    "internet_facing": true
  },
  "created": "2026-05-06T10:30:00Z"
}
```

**Output:**
```json
{
  "id": "TR-2026-0512",
  "severity": "CRITICAL",
  "score": 92,
  "breakdown": {
    "source_reliability": 25,
    "corroboration": 20,
    "time_sensitivity": 25,
    "asset_exposure": 22
  },
  "rationale": "Reliable source (A), 2 independent confirmations, active exploitation, internet-facing confidential systems"
}
```

---

## Open Questions

1. Should severity thresholds be configurable in Phase 1 or defer to Phase 3?
2. Should missing optional fields (e.g., no corroboration) warn or silently score 0?
