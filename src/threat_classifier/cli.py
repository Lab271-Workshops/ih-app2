from __future__ import annotations

import json
import sys
from dataclasses import asdict
from typing import Any

from .models import AssetExposure, ThreatReport
from .scorer import classify


def _parse_report(data: dict[str, Any]) -> ThreatReport:
    exposure_data = data.get("asset_exposure", {})
    exposure = AssetExposure(
        internet_facing=exposure_data.get("internet_facing", False),
        confidential=exposure_data.get("confidential", False),
        systems=exposure_data.get("systems", 0),
    )
    return ThreatReport(
        source_reliability=data["source_reliability"],
        corroborating_sources=data.get("corroborating_sources", 0),
        time_sensitivity=data["time_sensitivity"],
        asset_exposure=exposure,
    )


def _result_to_dict(result: Any) -> dict[str, Any]:
    d = asdict(result)
    # Flatten breakdown from nested dataclass
    d["breakdown"] = asdict(result.breakdown)
    d["breakdown"].pop("total", None)  # total is a property, not in asdict
    return d


def main() -> None:
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print(
            json.dumps({"error": "Usage: classify <file.json> or classify -"}),
            file=sys.stderr,
        )
        sys.exit(1)

    path = args[0]
    try:
        if path == "-":
            raw = sys.stdin.read()
        else:
            with open(path) as f:
                raw = f.read()
    except OSError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}))
        sys.exit(1)

    try:
        report = _parse_report(data)
        result = classify(report)
        output = {
            "severity": result.severity,
            "score": result.score,
            "breakdown": {
                "source_reliability": result.breakdown.source_reliability,
                "corroboration": result.breakdown.corroboration,
                "time_sensitivity": result.breakdown.time_sensitivity,
                "asset_exposure": result.breakdown.asset_exposure,
            },
            "rationale": result.rationale,
        }
        print(json.dumps(output))
    except (KeyError, ValueError, TypeError) as e:
        print(json.dumps({"error": f"Invalid report: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
