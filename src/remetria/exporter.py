"""
Remetria export helpers.

Writes machine-friendly JSON output and structured CSV tables from the current
analysis result.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from utils.paths import JSON_DIR, TABLES_DIR


# ------------------------------------------------------------
# OUTPUT PATHS
# ------------------------------------------------------------

ANALYSIS_JSON_PATH = JSON_DIR / "remetria_analysis.json"
SCAN_SUMMARY_TABLE_PATH = TABLES_DIR / "scan_summary.csv"
CVE_ROWS_TABLE_PATH = TABLES_DIR / "cve_rows.csv"
KB_CANDIDATES_TABLE_PATH = TABLES_DIR / "kb_candidates.csv"
CVE_ENRICHMENT_TABLE_PATH = TABLES_DIR / "cve_enrichment.csv"
ENRICHED_KB_CANDIDATES_TABLE_PATH = TABLES_DIR / "kb_candidates_enriched.csv"
RANKING_COMPARISON_TABLE_PATH = TABLES_DIR / "ranking_comparison.csv"


# ------------------------------------------------------------
# JSON SERIALISATION
# ------------------------------------------------------------

def make_json_safe(value: Any) -> Any:
    """Return a JSON-safe value."""

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            key: make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            make_json_safe(item)
            for item in value
        ]

    return value


# ------------------------------------------------------------
# JSON EXPORT
# ------------------------------------------------------------

def write_json_output(analysis_result: dict[str, Any]) -> Path:
    """Write the full Remetria analysis result as JSON."""

    JSON_DIR.mkdir(parents=True, exist_ok=True)

    with ANALYSIS_JSON_PATH.open("w", encoding="utf-8") as file:
        json.dump(
            make_json_safe(analysis_result),
            file,
            indent=2,
            ensure_ascii=False,
        )

    return ANALYSIS_JSON_PATH


# ------------------------------------------------------------
# CSV EXPORT
# ------------------------------------------------------------

def collect_fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    """Return stable CSV fieldnames from row dictionaries."""

    fieldnames: list[str] = []

    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    return fieldnames


def write_csv_table(path: Path, rows: list[dict[str, Any]]) -> Path:
    """Write one CSV table from row dictionaries."""

    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = collect_fieldnames(rows)

    with path.open("w", encoding="utf-8", newline="") as file:
        if not fieldnames:
            return path

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)

    return path


def write_csv_outputs(analysis_result: dict[str, Any]) -> dict[str, Path]:
    """Write Remetria CSV table outputs."""

    scan_summary_path = write_csv_table(
        path=SCAN_SUMMARY_TABLE_PATH,
        rows=analysis_result["ScanSummaryRows"],
    )

    cve_rows_path = write_csv_table(
        path=CVE_ROWS_TABLE_PATH,
        rows=analysis_result["CveRows"],
    )

    kb_candidates_path = write_csv_table(
        path=KB_CANDIDATES_TABLE_PATH,
        rows=analysis_result["KbCandidateRows"],
    )

    cve_enrichment_path = write_csv_table(
        path=CVE_ENRICHMENT_TABLE_PATH,
        rows=analysis_result["CveEnrichmentRows"],
    )

    enriched_kb_candidates_path = write_csv_table(
        path=ENRICHED_KB_CANDIDATES_TABLE_PATH,
        rows=analysis_result["EnrichedKbCandidateRows"],
    )
    ranking_comparison_path = write_csv_table(
        path=RANKING_COMPARISON_TABLE_PATH,
        rows=analysis_result["RankingComparisonRows"],
    )

    return {
        "ScanSummary": scan_summary_path,
        "CveRows": cve_rows_path,
        "KbCandidates": kb_candidates_path,
        "CveEnrichment": cve_enrichment_path,
        "EnrichedKbCandidates": enriched_kb_candidates_path,
        "RankingComparison": ranking_comparison_path,
    }


# ------------------------------------------------------------
# EXPORT WORKFLOW
# ------------------------------------------------------------

def export_analysis_result(analysis_result: dict[str, Any]) -> dict[str, Any]:
    """Export the current Remetria analysis result."""

    json_path = write_json_output(analysis_result)
    csv_paths = write_csv_outputs(analysis_result)

    return {
        "JsonPath": json_path,
        "CsvPaths": csv_paths,
    }