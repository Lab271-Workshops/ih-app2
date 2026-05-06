from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

SourceReliability = Literal["A", "B", "C", "D", "E", "F"]
TimeSensitivity = Literal["active", "<7d", "<30d", "other"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass
class AssetExposure:
    internet_facing: bool = False
    confidential: bool = False
    systems: int = 0  # number of affected systems


@dataclass
class ThreatReport:
    source_reliability: SourceReliability
    corroborating_sources: int  # number of independent sources
    time_sensitivity: TimeSensitivity
    asset_exposure: AssetExposure = field(default_factory=AssetExposure)


@dataclass
class ScoreBreakdown:
    source_reliability: int
    corroboration: int
    time_sensitivity: int
    asset_exposure: int

    @property
    def total(self) -> int:
        return (
            self.source_reliability
            + self.corroboration
            + self.time_sensitivity
            + self.asset_exposure
        )


@dataclass
class ClassificationResult:
    severity: Severity
    score: int
    breakdown: ScoreBreakdown
    rationale: str
