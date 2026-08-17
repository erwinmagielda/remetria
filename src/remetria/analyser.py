"""
Remetria analysis workflow.

Provides the main menu and active runtime dataset intake flow.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from processing.builder import build_kb_candidate_rows
from processing.enricher import enrich_analysis_rows
from processing.evaluator import evaluate_ranking_comparison
from processing.loader import load_runtime_scans
from processing.normaliser import normalise_loaded_scans
from processing.ranker import rank_enriched_kb_candidates
from remetria.cleaner import clear_generated_artefacts
from remetria.exporter import export_analysis_result
from remetria.reporter import write_markdown_report
from utils.console import (
    print_action,
    print_banner,
    print_detail,
    print_error,
    print_info,
    print_menu_title,
    print_result,
    print_section,
    print_step,
    print_success,
    prompt_main_menu,
)
from utils.paths import ensure_output_directories, ensure_required_directories, relative_path


# ------------------------------------------------------------
# SCAN DISPLAY
# ------------------------------------------------------------

def print_loaded_scan_details(loaded_scans: list[dict[str, Any]]) -> None:
    """Print accepted runtime scan records."""

    for scan_record in loaded_scans:
        scan_id = scan_record["ScanId"]
        scan_path = scan_record["ScanPath"]

        print_detail(f"Scan ID: {scan_id}")
        print_detail(f"Source: {relative_path(scan_path)}")


# ------------------------------------------------------------
# ANALYSIS RESULT
# ------------------------------------------------------------

def build_analysis_result(
    loaded_scans: list[dict[str, Any]],
    normalised_result: dict[str, list[dict[str, Any]]],
    kb_candidate_rows: list[dict[str, Any]],
    enrichment_result: dict[str, list[dict[str, Any]]],
    ranking_comparison_rows: list[dict[str, Any]],
    evaluation_metric_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the current Remetria machine-friendly analysis result."""

    scan_ids = [
        scan_record["ScanId"]
        for scan_record in loaded_scans
    ]

    return {
        "Tool": "Remetria",
        "ResultType": "RuntimeEvaluationBuild",
        "GeneratedUtc": datetime.now(timezone.utc).isoformat(),
        "RuntimeScanCount": len(loaded_scans),
        "ScanIds": scan_ids,
        "ScanSummaryRows": normalised_result["ScanSummaryRows"],
        "CveRows": normalised_result["CveRows"],
        "KbCandidateRows": kb_candidate_rows,
        "CveEnrichmentRows": enrichment_result["CveEnrichmentRows"],
        "EnrichedKbCandidateRows": enrichment_result["EnrichedKbCandidateRows"],
        "RankingComparisonRows": ranking_comparison_rows,
        "EvaluationMetricRows": evaluation_metric_rows,
    }

def print_export_details(export_result: dict[str, Any]) -> None:
    """Print generated export paths."""

    json_path = export_result["JsonPath"]
    csv_paths = export_result["CsvPaths"]

    print_detail(f"JSON: {relative_path(json_path)}")

    for table_path in csv_paths.values():
        print_detail(f"Table: {relative_path(table_path)}")


# ------------------------------------------------------------
# ANALYSIS WORKFLOW
# ------------------------------------------------------------

def run_analysis() -> None:
    """Run the Remetria analysis workflow."""

    print_action("Run Analysis")

    print_section("Environment Preparation")

    print_step("Validating required directories")
    ensure_required_directories()
    print_result("Required directories found")

    print_step("Preparing output directories")
    ensure_output_directories()
    print_result("Output directories prepared")

    print_section("Runtime Dataset")

    print_step("Loading active runtime scans")
    loaded_scans = load_runtime_scans()
    print_result("Runtime scans loaded")
    print_detail(f"Scans loaded: {len(loaded_scans)}")

    print_loaded_scan_details(loaded_scans)

    print_section("Evidence Normalisation")

    print_step("Normalising loaded scan evidence")
    normalised_result = normalise_loaded_scans(loaded_scans)
    print_result("Loaded scan evidence normalised")
    print_detail(f"Scan summary rows: {len(normalised_result['ScanSummaryRows'])}")
    print_detail(f"CVE rows: {len(normalised_result['CveRows'])}")

    print_section("Candidate Build")

    print_step("Building missing KB candidate rows")
    kb_candidate_rows = build_kb_candidate_rows(loaded_scans)
    print_result("Missing KB candidate rows built")
    print_detail(f"KB candidate rows: {len(kb_candidate_rows)}")

    print_section("Evidence Enrichment")

    print_step("Enriching CVE metadata from MSRC CVRF evidence")
    enrichment_result = enrich_analysis_rows(
        cve_rows=normalised_result["CveRows"],
        kb_candidate_rows=kb_candidate_rows,
    )
    print_result("CVE metadata enrichment completed")
    print_detail(f"CVE enrichment rows: {len(enrichment_result['CveEnrichmentRows'])}")
    print_detail(
        "Enriched KB candidate rows: "
        f"{len(enrichment_result['EnrichedKbCandidateRows'])}"
    )

    print_section("Ranking Comparison")

    print_step("Ranking enriched KB candidates")
    ranking_comparison_rows = rank_enriched_kb_candidates(
        enrichment_result["EnrichedKbCandidateRows"]
    )
    print_result("Ranking comparison completed")
    print_detail(f"Ranking comparison rows: {len(ranking_comparison_rows)}")

    print_section("Ranking Evaluation")

    print_step("Evaluating ranking comparison")
    evaluation_metric_rows = evaluate_ranking_comparison(
        ranking_comparison_rows
    )
    print_result("Ranking evaluation completed")
    print_detail(f"Evaluation metric rows: {len(evaluation_metric_rows)}")

    print_section("Analysis Result")

    print_step("Building machine-friendly analysis result")
    analysis_result = build_analysis_result(
        loaded_scans=loaded_scans,
        normalised_result=normalised_result,
        kb_candidate_rows=kb_candidate_rows,
        enrichment_result=enrichment_result,
        ranking_comparison_rows=ranking_comparison_rows,
        evaluation_metric_rows=evaluation_metric_rows,
    )
    print_result("Machine-friendly analysis result built")

    print_section("Runtime Export")

    print_step("Writing Remetria output files")
    export_result = export_analysis_result(analysis_result)
    print_result("Remetria output files written")
    print_export_details(export_result)

    print_section("Markdown Report")

    print_step("Writing Remetria Markdown report")
    report_path = write_markdown_report(analysis_result)
    print_result("Markdown report written")
    print_detail(f"Report: {relative_path(report_path)}")

    print_section("Analysis Status")

    print_info("Remetria analytical workflow completed")
    print_info("Next step: inspect report output, then freeze pre-update results")

    print_success("Run Analysis completed")


# ------------------------------------------------------------
# ARTEFACT CLEANUP
# ------------------------------------------------------------

def clear_artefacts() -> None:
    """Run the clear artefacts workflow."""

    result = clear_generated_artefacts()

    if result == "cleared":
        print_success("Clear Artefacts completed")
        return

    if result == "cancelled":
        print_info("Clear Artefacts cancelled")
        return

    print_info("Clear Artefacts skipped")


# ------------------------------------------------------------
# MAIN MENU
# ------------------------------------------------------------

def main() -> None:
    """Run the Remetria main menu."""

    print_banner()

    while True:
        selection = prompt_main_menu()

        if selection == "1":
            try:
                run_analysis()
            except RuntimeError as exc:
                print_error(str(exc))

            print_menu_title()

        elif selection == "2":
            try:
                clear_artefacts()
            except RuntimeError as exc:
                print_error(str(exc))

            print_menu_title()

        elif selection == "3":
            print_info("Exit")
            break

        else:
            print_error("Invalid option")
            print_menu_title()


if __name__ == "__main__":
    main()