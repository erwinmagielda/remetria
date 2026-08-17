"""
Remetria analysis workflow.

Provides the main menu and active runtime dataset analysis flow.
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

    print_section("Environment")

    print_step("Preparing environment")
    ensure_required_directories()
    ensure_output_directories()
    print_result("Environment ready")

    print_section("Runtime Dataset")

    print_step("Loading runtime scans")
    loaded_scans = load_runtime_scans()
    print_result(f"Scans loaded: {len(loaded_scans)}")

    print_section("Evidence Processing")

    print_step("Normalising scan evidence")
    normalised_result = normalise_loaded_scans(loaded_scans)
    print_result(f"Scan summary rows: {len(normalised_result['ScanSummaryRows'])}")
    print_result(f"CVE evidence rows: {len(normalised_result['CveRows'])}")

    print_step("Building missing KB candidates")
    kb_candidate_rows = build_kb_candidate_rows(loaded_scans)
    print_result(f"Missing KB candidates: {len(kb_candidate_rows)}")

    print_section("Enrichment")

    print_step("Enriching CVE metadata")
    enrichment_result = enrich_analysis_rows(
        cve_rows=normalised_result["CveRows"],
        kb_candidate_rows=kb_candidate_rows,
    )
    print_result(f"Unique CVEs enriched: {len(enrichment_result['CveEnrichmentRows'])}")
    print_result(
        "Enriched KB candidates: "
        f"{len(enrichment_result['EnrichedKbCandidateRows'])}"
    )

    print_section("Ranking and Evaluation")

    print_step("Ranking candidates")
    ranking_comparison_rows = rank_enriched_kb_candidates(
        enrichment_result["EnrichedKbCandidateRows"]
    )
    print_result(f"Ranking rows: {len(ranking_comparison_rows)}")

    print_step("Evaluating rankings")
    evaluation_metric_rows = evaluate_ranking_comparison(
        ranking_comparison_rows
    )
    print_result(f"Evaluation rows: {len(evaluation_metric_rows)}")

    print_section("Output")

    print_step("Building analysis result")
    analysis_result = build_analysis_result(
        loaded_scans=loaded_scans,
        normalised_result=normalised_result,
        kb_candidate_rows=kb_candidate_rows,
        enrichment_result=enrichment_result,
        ranking_comparison_rows=ranking_comparison_rows,
        evaluation_metric_rows=evaluation_metric_rows,
    )
    print_result("Analysis result built")

    print_step("Writing JSON and CSV outputs")
    export_result = export_analysis_result(analysis_result)
    print_result("JSON and CSV outputs written")
    print_export_details(export_result)

    print_step("Writing Markdown report")
    report_path = write_markdown_report(analysis_result)
    print_result("Markdown report written")
    print_detail(f"Report: {relative_path(report_path)}")

    print_section("Analysis Status")

    print_success("Remetria workflow completed")


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