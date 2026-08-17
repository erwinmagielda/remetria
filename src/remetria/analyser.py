"""
Remetria analysis workflow.

Provides the main menu and active runtime dataset analysis flow.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from processing.builder import build_kb_candidate_rows
from processing.enricher import enrich_analysis_rows
from processing.evaluator import evaluate_ranking_comparison
from processing.loader import load_runtime_scans
from processing.normaliser import normalise_loaded_scans
from processing.ranker import rank_enriched_kb_candidates
from remetria.cleaner import clear_generated_artefacts
from remetria.exporter import (
    build_export_context,
    ensure_export_directories,
    write_csv_outputs,
    write_json_output,
)
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
from utils.paths import (
    RUNTIME_DIR,
    build_analysis_run_id,
    ensure_required_directories,
    ensure_results_directory,
    get_utc_timestamp,
    relative_path,
)


# ------------------------------------------------------------
# METRIC HELPERS
# ------------------------------------------------------------

def count_candidate_bearing_scans(
    kb_candidate_rows: list[dict[str, Any]],
) -> int:
    """Return the number of scans with at least one missing KB candidate."""

    return len({
        row.get("ScanId")
        for row in kb_candidate_rows
        if row.get("ScanId")
    })


def count_missing_enrichment_rows(
    enrichment_rows: list[dict[str, Any]],
) -> int:
    """Return the number of CVE enrichment rows not resolved."""

    return len([
        row
        for row in enrichment_rows
        if row.get("EnrichmentStatus") != "resolved"
    ])


def find_aggregate_evaluation_row(
    evaluation_metric_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the aggregate evaluation row when present."""

    for row in evaluation_metric_rows:
        if row.get("EvaluationScope") == "aggregate":
            return row

    return {}


def format_ratio(value: Any) -> str:
    """Return a ratio formatted for console output."""

    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return "n/a"


# ------------------------------------------------------------
# ANALYSIS RESULT
# ------------------------------------------------------------

def build_analysis_result(
    generated_utc: datetime,
    export_context: dict[str, Any],
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
        "RunId": export_context["RunId"],
        "GeneratedUtc": generated_utc.isoformat(),
        "RuntimeInput": relative_path(RUNTIME_DIR),
        "OutputRoot": relative_path(export_context["OutputRoot"]),
        "OutputPaths": {
            "JsonPath": relative_path(export_context["JsonPath"]),
            "TablesDir": relative_path(export_context["TablesDir"]),
            "ReportPath": relative_path(export_context["ReportPath"]),
        },
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


# ------------------------------------------------------------
# ANALYSIS WORKFLOW
# ------------------------------------------------------------

def run_analysis() -> None:
    """Run the Remetria analysis workflow."""

    print_action("Run Analysis")

    generated_utc = get_utc_timestamp()
    run_id = build_analysis_run_id(generated_utc)
    export_context = build_export_context(run_id)

    print_section("Environment Preparation")
    print_step("Validating analyser workspace")
    ensure_required_directories()
    ensure_results_directory()
    print_detail("Source path: src")
    print_detail(f"Runtime input: {relative_path(RUNTIME_DIR)}")
    print_detail(f"Output root: {relative_path(export_context['OutputRoot'])}")
    print_detail(f"Run ID: {run_id}")
    print_result("Analysis workspace prepared")

    print_section("Runtime Input")
    print_step("Loading Kolektria scan evidence")
    loaded_scans = load_runtime_scans()
    print_detail(f"Source folder: {relative_path(RUNTIME_DIR)}")
    print_detail(f"Scan files loaded: {len(loaded_scans)}")
    print_result("Runtime scans loaded")

    print_section("Evidence Normalisation")
    print_step("Normalising scan and CVE rows")
    normalised_result = normalise_loaded_scans(loaded_scans)
    print_detail(f"Scan summary rows: {len(normalised_result['ScanSummaryRows'])}")
    print_detail(f"CVE evidence rows: {len(normalised_result['CveRows'])}")
    print_result("Evidence rows normalised")

    print_section("Candidate Analysis")
    print_step("Building missing KB candidates")
    kb_candidate_rows = build_kb_candidate_rows(loaded_scans)
    candidate_bearing_scan_count = count_candidate_bearing_scans(kb_candidate_rows)
    print_detail(f"Candidate-bearing scans: {candidate_bearing_scan_count}")
    print_detail(f"Missing KB candidates: {len(kb_candidate_rows)}")
    print_result("Candidate set built")

    print_section("CVE Enrichment")
    print_step("Resolving CVE metadata")
    enrichment_result = enrich_analysis_rows(
        cve_rows=normalised_result["CveRows"],
        kb_candidate_rows=kb_candidate_rows,
    )
    missing_enrichment_rows = count_missing_enrichment_rows(
        enrichment_result["CveEnrichmentRows"]
    )
    print_detail(f"Unique CVEs enriched: {len(enrichment_result['CveEnrichmentRows'])}")
    print_detail(f"Missing enrichment rows: {missing_enrichment_rows}")
    print_result("CVE metadata resolved")

    print_section("Ranking Comparison")
    print_step("Comparing CVSS, MSRC and CPRI rankings")
    ranking_comparison_rows = rank_enriched_kb_candidates(
        enrichment_result["EnrichedKbCandidateRows"]
    )
    print_detail(f"Ranking rows: {len(ranking_comparison_rows)}")
    print_detail(f"Candidate-bearing scans: {candidate_bearing_scan_count}")
    print_result("Ranking comparison completed")

    print_section("Evaluation Metrics")
    print_step("Calculating ranking metrics")
    evaluation_metric_rows = evaluate_ranking_comparison(
        ranking_comparison_rows
    )
    aggregate_row = find_aggregate_evaluation_row(evaluation_metric_rows)
    print_detail(f"Evaluation rows: {len(evaluation_metric_rows)}")
    print_detail(
        "CPRI/CVSS Top-Ranked KB Agreement: "
        f"{format_ratio(aggregate_row.get('CVSSTop1MatchRatio'))}"
    )
    print_detail(
        "CPRI/MSRC Top-Ranked KB Agreement: "
        f"{format_ratio(aggregate_row.get('MSRCTop1MatchRatio'))}"
    )
    print_result("Evaluation metrics calculated")

    print_section("Runtime Export")
    ensure_export_directories(export_context)

    analysis_result = build_analysis_result(
        generated_utc=generated_utc,
        export_context=export_context,
        loaded_scans=loaded_scans,
        normalised_result=normalised_result,
        kb_candidate_rows=kb_candidate_rows,
        enrichment_result=enrichment_result,
        ranking_comparison_rows=ranking_comparison_rows,
        evaluation_metric_rows=evaluation_metric_rows,
    )

    print_step("Writing analysis JSON")
    write_json_output(
        path=export_context["JsonPath"],
        analysis_result=analysis_result,
    )
    print_detail(f"JSON: {relative_path(export_context['JsonPath'])}")
    print_result("Analysis JSON written")

    print()

    print_step("Writing CSV tables")
    write_csv_outputs(
        csv_paths=export_context["CsvPaths"],
        analysis_result=analysis_result,
    )
    print_detail(f"Tables: {relative_path(export_context['TablesDir'])}")
    print_result("CSV tables written")

    print()

    print_step("Writing Markdown report")
    write_markdown_report(
        analysis_result=analysis_result,
        report_path=export_context["ReportPath"],
    )
    print_detail(f"Markdown report: {relative_path(export_context['ReportPath'])}")
    print_result("Markdown report written")

    print()
    print_success("Run Analysis completed")


# ------------------------------------------------------------
# ARTEFACT CLEANUP
# ------------------------------------------------------------

def clear_artefacts() -> None:
    """Run the clear artefacts workflow."""

    result = clear_generated_artefacts()

    if result == "cleared":
        print()
        print_success("Clear Artefacts completed")
        return

    if result == "cancelled":
        print()
        print_info("Clear Artefacts cancelled")
        return

    print()
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