import json
import subprocess
import sys
from pathlib import Path


def run_classify(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "threat_classifier.cli", *args]
    return subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        text=True,
    )


VALID_REPORT = {
    "source_reliability": "A",
    "corroborating_sources": 2,
    "time_sensitivity": "active",
    "asset_exposure": {
        "internet_facing": True,
        "confidential": True,
        "systems": 1,
    },
}


class TestCLIFileInput:
    def test_classify_file(self, tmp_path: Path):
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(VALID_REPORT))
        result = run_classify(str(report_file))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert isinstance(data["score"], int)

    def test_output_has_breakdown(self, tmp_path: Path):
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(VALID_REPORT))
        result = run_classify(str(report_file))
        data = json.loads(result.stdout)
        bd = data["breakdown"]
        expected_keys = {
            "source_reliability", "corroboration", "time_sensitivity", "asset_exposure"
        }
        assert set(bd.keys()) == expected_keys
        assert sum(bd.values()) == data["score"]

    def test_output_has_rationale(self, tmp_path: Path):
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(VALID_REPORT))
        result = run_classify(str(report_file))
        data = json.loads(result.stdout)
        assert isinstance(data["rationale"], str)
        assert len(data["rationale"]) > 0

    def test_missing_file_exits_nonzero(self):
        result = run_classify("/nonexistent/report.json")
        assert result.returncode != 0
        data = json.loads(result.stdout)
        assert "error" in data

    def test_invalid_json_exits_nonzero(self, tmp_path: Path):
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json{{{")
        result = run_classify(str(bad_file))
        assert result.returncode != 0
        data = json.loads(result.stdout)
        assert "error" in data

    def test_missing_required_field_exits_nonzero(self, tmp_path: Path):
        bad_report = tmp_path / "bad.json"
        bad_report.write_text(json.dumps({"corroborating_sources": 1}))
        result = run_classify(str(bad_report))
        assert result.returncode != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestCLIStdinInput:
    def test_classify_stdin(self):
        result = run_classify("-", stdin=json.dumps(VALID_REPORT))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_stdin_invalid_json(self):
        result = run_classify("-", stdin="not json")
        assert result.returncode != 0
        data = json.loads(result.stdout)
        assert "error" in data


class TestCLIOutputFormat:
    def test_output_is_valid_json(self, tmp_path: Path):
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(VALID_REPORT))
        result = run_classify(str(report_file))
        # Should not raise
        json.loads(result.stdout)

    def test_no_extra_output_on_success(self, tmp_path: Path):
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(VALID_REPORT))
        result = run_classify(str(report_file))
        # stdout should be exactly one JSON object
        data = json.loads(result.stdout)
        assert isinstance(data, dict)
