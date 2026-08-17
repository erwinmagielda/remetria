"""
Remetria output exporter.

Writes the current Remetria analysis result into a timestamped analysis folder
under results/.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from utils.paths import RESULTS_DIR


# ------------------------------------------------------------
# OUTPUT TABLE MAP
# ------------------------------------------------------------

CSV_TABLES = {
    "scan_summary.csv": "ScanSummaryRows",
    "cve_rows.csv": "CveRows",
    "kb_candidates.csv": "KbCandidateRows",
    "cve_enrichment.csv": "CveEnrichmentRows",
    "kb_candidates_enriched.csv": "EnrichedKbCandidateRows",
    "ranking_comparison.csv": "RankingComparisonRows",
    "evaluation_metrics.csv": "EvaluationMetricRows",
}


# ------------------------------------------------------------
# EXPORT CONTEXT
# ------------------------------------------------------------

def build_export_context(run_id: str) -> dict[str, Any]:
    """Build timestamped output paths for one Remetria analysis run."""

    output_root = RESULTS_DIR / run_id
    json_dir = output_root / "json"
    tables_dir = output_root / "tables"
    reports_dir = output_root / "reports"

    return {
        "RunId": run_id,
        "OutputRoot": output_root,
        "JsonDir": json_dir,
        "TablesDir": tables_dir,
        "ReportsDir": reports_dir,
        "JsonPath": json_dir / "remetria_analysis.json",
        "ReportPath": reports_dir / "remetria_report.md",
        "CsvPaths": {
            filename: tables_dir / filename
            for filename in CSV_TABLES
        },
    }


def ensure_export_directories(export_context: dict[str, Any]) -> None:
    """Create timestamped output directories for one analysis run."""

    export_context["JsonDir"].mkdir(parents=True, exist_ok=True)
    export_context["TablesDir"].mkdir(parents=True, exist_ok=True)
    export_context["ReportsDir"].mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------
# JSON EXPORT
# ------------------------------------------------------------

def serialise_value(value: Any) -> Any:
    """Return a JSON-safe value."""

    if isinstance(value, Path):
        return str(value)

    return value


def write_json_output(path: Path, analysis_result: dict[str, Any]) -> None:
    """Write the full Remetria analysis result as JSON."""

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            analysis_result,
            file,
            indent=2,
            ensure_ascii=False,
            default=serialise_value,
        )


# ------------------------------------------------------------
# CSV EXPORT
# ------------------------------------------------------------

def get_fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    """Return stable CSV fieldnames from row keys."""

    fieldnames: list[str] = []

    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    return fieldnames


def write_csv_output(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write a Remetria row set as CSV."""

    with path.open("w", encoding="utf-8", newline="") as file:
        if not rows:
            file.write("")
            return

        fieldnames = get_fieldnames(rows)

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_csv_outputs(
    csv_paths: dict[str, Path],
    analysis_result: dict[str, Any],
) -> None:
    """Write all Remetria table outputs."""

    for filename, result_key in CSV_TABLES.items():
        rows = analysis_result.get(result_key, [])

        if not isinstance(rows, list):
            rows = []

        write_csv_output(csv_paths[filename], rows)


# ------------------------------------------------------------
# EXPORT WORKFLOW
# ------------------------------------------------------------

def export_analysis_result(
    analysis_result: dict[str, Any],
    export_context: dict[str, Any],
) -> dict[str, Any]:
    """Export the current Remetria analysis result."""

    ensure_export_directories(export_context)

    write_json_output(
        path=export_context["JsonPath"],
        analysis_result=analysis_result,
    )
    write_csv_outputs(
        csv_paths=export_context["CsvPaths"],
        analysis_result=analysis_result,
    )

    return export_context