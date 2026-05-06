
from threat_classifier.models import AssetExposure, ThreatReport
from threat_classifier.scorer import (
    _score_corroboration,
    _score_exposure,
    _score_source,
    _score_time,
    classify,
)


class TestSourceScoring:
    def test_grade_a(self):
        assert _score_source("A") == 25

    def test_grade_b(self):
        assert _score_source("B") == 20

    def test_grade_c(self):
        assert _score_source("C") == 15

    def test_grade_d(self):
        assert _score_source("D") == 10

    def test_grade_e(self):
        assert _score_source("E") == 5

    def test_grade_f(self):
        assert _score_source("F") == 0


class TestCorroborationScoring:
    def test_zero_sources(self):
        assert _score_corroboration(0) == 0

    def test_one_source(self):
        assert _score_corroboration(1) == 10

    def test_two_sources(self):
        assert _score_corroboration(2) == 20

    def test_capped_at_20(self):
        assert _score_corroboration(5) == 20


class TestTimeScoring:
    def test_active(self):
        assert _score_time("active") == 25

    def test_within_7_days(self):
        assert _score_time("<7d") == 20

    def test_within_30_days(self):
        assert _score_time("<30d") == 15

    def test_other(self):
        assert _score_time("other") == 10


class TestExposureScoring:
    def test_no_exposure(self):
        assert _score_exposure(AssetExposure()) == 0

    def test_internet_facing(self):
        assert _score_exposure(AssetExposure(internet_facing=True)) == 10

    def test_confidential(self):
        assert _score_exposure(AssetExposure(confidential=True)) == 10

    def test_both_internet_and_confidential(self):
        exposure = AssetExposure(internet_facing=True, confidential=True)
        assert _score_exposure(exposure) == 20

    def test_systems(self):
        assert _score_exposure(AssetExposure(systems=1)) == 5

    def test_systems_two(self):
        assert _score_exposure(AssetExposure(systems=2)) == 10

    def test_systems_three(self):
        assert _score_exposure(AssetExposure(systems=3)) == 15

    def test_capped_at_25(self):
        exposure = AssetExposure(internet_facing=True, confidential=True, systems=5)
        assert _score_exposure(exposure) == 25


class TestClassify:
    def _make_report(self, **kwargs) -> ThreatReport:
        defaults = dict(
            source_reliability="A",
            corroborating_sources=2,
            time_sensitivity="active",
            asset_exposure=AssetExposure(internet_facing=True, confidential=True),
        )
        defaults.update(kwargs)
        return ThreatReport(**defaults)

    def test_critical_threshold(self):
        report = self._make_report()
        result = classify(report)
        assert result.severity == "CRITICAL"
        assert result.score >= 80

    def test_breakdown_sums_to_score(self):
        report = self._make_report()
        result = classify(report)
        bd = result.breakdown
        total = (
            bd.source_reliability
            + bd.corroboration
            + bd.time_sensitivity
            + bd.asset_exposure
        )
        assert total == result.score

    def test_low_severity(self):
        report = ThreatReport(
            source_reliability="F",
            corroborating_sources=0,
            time_sensitivity="other",
            asset_exposure=AssetExposure(),
        )
        result = classify(report)
        assert result.severity == "LOW"
        assert result.score < 40

    def test_medium_severity(self):
        # Score around 40-59
        report = ThreatReport(
            source_reliability="C",
            corroborating_sources=1,
            time_sensitivity="other",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        # C=15, 1 src=10, other=10, internet=10 → 45
        assert result.severity == "MEDIUM"
        assert 40 <= result.score < 60

    def test_high_severity(self):
        # Score around 60-79
        report = ThreatReport(
            source_reliability="B",
            corroborating_sources=2,
            time_sensitivity="<7d",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        # B=20, 2 src=20, <7d=20, internet=10 → 70
        assert result.severity == "HIGH"
        assert 60 <= result.score < 80

    def test_rationale_is_string(self):
        report = self._make_report()
        result = classify(report)
        assert isinstance(result.rationale, str)
        assert len(result.rationale) > 0

    def test_rationale_mentions_source(self):
        report = self._make_report(source_reliability="A")
        result = classify(report)
        assert "(A)" in result.rationale

    # Threshold boundary tests
    def test_score_80_is_critical(self):
        # A(25) + 2src(20) + active(25) + internet(10) = 80
        report = ThreatReport(
            source_reliability="A",
            corroborating_sources=2,
            time_sensitivity="active",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        assert result.score == 80
        assert result.severity == "CRITICAL"

    def test_score_75_is_high(self):
        # A(25) + 2src(20) + <7d(20) + confidential(10) = 75
        report = ThreatReport(
            source_reliability="A",
            corroborating_sources=2,
            time_sensitivity="<7d",
            asset_exposure=AssetExposure(confidential=True),
        )
        result = classify(report)
        assert result.score == 75
        assert result.severity == "HIGH"

    def test_score_60_is_high(self):
        # B(20) + 1src(10) + <30d(15) + internet(10) + systems(1*5=5) = 60
        report = ThreatReport(
            source_reliability="B",
            corroborating_sources=1,
            time_sensitivity="<30d",
            asset_exposure=AssetExposure(internet_facing=True, systems=1),
        )
        result = classify(report)
        assert result.score == 60
        assert result.severity == "HIGH"

    def test_score_55_is_medium(self):
        # C(15) + 1src(10) + <7d(20) + internet(10) = 55
        report = ThreatReport(
            source_reliability="C",
            corroborating_sources=1,
            time_sensitivity="<7d",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        assert result.score == 55
        assert result.severity == "MEDIUM"

    def test_score_40_is_medium(self):
        # D(10) + 1src(10) + other(10) + internet(10) = 40
        report = ThreatReport(
            source_reliability="D",
            corroborating_sources=1,
            time_sensitivity="other",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        assert result.score == 40
        assert result.severity == "MEDIUM"

    def test_score_35_is_low(self):
        # E(5) + 1src(10) + other(10) + internet(10) = 35
        report = ThreatReport(
            source_reliability="E",
            corroborating_sources=1,
            time_sensitivity="other",
            asset_exposure=AssetExposure(internet_facing=True),
        )
        result = classify(report)
        assert result.score == 35
        assert result.severity == "LOW"
