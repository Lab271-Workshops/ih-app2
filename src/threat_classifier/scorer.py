from __future__ import annotations

from .models import (
    AssetExposure,
    ClassificationResult,
    ScoreBreakdown,
    Severity,
    ThreatReport,
)

_SOURCE_SCORES: dict[str, int] = {
    "A": 25,
    "B": 20,
    "C": 15,
    "D": 10,
    "E": 5,
    "F": 0,
}

_TIME_SCORES: dict[str, int] = {
    "active": 25,
    "<7d": 20,
    "<30d": 15,
    "other": 10,
}

_THRESHOLDS: list[tuple[int, Severity]] = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
]


def _score_source(reliability: str) -> int:
    return _SOURCE_SCORES.get(reliability, 0)


def _score_corroboration(sources: int) -> int:
    return min(sources * 10, 20)


def _score_time(sensitivity: str) -> int:
    return _TIME_SCORES.get(sensitivity, 10)


def _score_exposure(exposure: AssetExposure) -> int:
    score = 0
    if exposure.internet_facing:
        score += 10
    if exposure.confidential:
        score += 10
    score += min(exposure.systems * 5, 5)  # +5 per system, cap at 5
    return min(score, 25)


def _to_severity(score: int) -> Severity:
    for threshold, severity in _THRESHOLDS:
        if score >= threshold:
            return severity
    return "LOW"


def _build_rationale(report: ThreatReport, breakdown: ScoreBreakdown) -> str:
    parts: list[str] = []

    rel = report.source_reliability
    if rel in ("A", "B"):
        label = "Reliable"
    elif rel in ("C", "D"):
        label = "Moderate"
    else:
        label = "Unreliable"
    parts.append(f"{label} source ({rel})")

    n = report.corroborating_sources
    if n >= 2:
        parts.append(f"{n} independent confirmations")
    elif n == 1:
        parts.append("1 independent confirmation")
    else:
        parts.append("no corroboration")

    ts = report.time_sensitivity
    ts_label = {
        "active": "active exploitation",
        "<7d": "reported within 7 days",
        "<30d": "reported within 30 days",
        "other": "older report",
    }.get(ts, ts)
    parts.append(ts_label)

    exp = report.asset_exposure
    exp_parts: list[str] = []
    if exp.internet_facing:
        exp_parts.append("internet-facing")
    if exp.confidential:
        exp_parts.append("confidential")
    if exp.systems > 0:
        exp_parts.append(f"{exp.systems} system(s)")
    if exp_parts:
        parts.append(" ".join(exp_parts) + " assets")

    return ", ".join(parts)


def classify(report: ThreatReport) -> ClassificationResult:
    breakdown = ScoreBreakdown(
        source_reliability=_score_source(report.source_reliability),
        corroboration=_score_corroboration(report.corroborating_sources),
        time_sensitivity=_score_time(report.time_sensitivity),
        asset_exposure=_score_exposure(report.asset_exposure),
    )
    score = breakdown.total
    severity = _to_severity(score)
    rationale = _build_rationale(report, breakdown)
    return ClassificationResult(
        severity=severity,
        score=score,
        breakdown=breakdown,
        rationale=rationale,
    )
