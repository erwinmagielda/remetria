"""
Remetria Markdown reporter.

Writes a focused analysis report from the current in-memory Remetria result.
The report presents Remetria's added analytical output: candidate generation,
CVE enrichment, CVSS/MSRC/CPRI ranking, evaluation metrics, interpretation,
and limitations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.paths import REPORTS_DIR


# ------------------------------------------------------------
# OUTPUT PATH
# ------------------------------------------------------------

REPORT_PATH = REPORTS_DIR / "remetria_report.md"


# ------------------------------------------------------------
# VALUE HELPERS
# ------------------------------------------------------------

def text(value: Any) -> str:
    """Return a clean string value."""

    if value is None:
        return ""

    return str(value)


def as_float(value: Any) -> float:
    """Return a numeric value as float, or zero when conversion fails."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def as_int(value: Any) -> int:
    """Return a numeric value as int, or zero when conversion fails."""

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def bool_label(value: Any) -> str:
    """Return Yes or No for boolean-like values."""

    if value is True:
        return "Yes"

    if value is False:
        return "No"

    if text(value).lower() == "true":
        return "Yes"

    if text(value).lower() == "false":
        return "No"

    return text(value)


def format_number(value: Any) -> str:
    """Return a compact display number."""

    number = as_float(value)

    if number.is_integer():
        return str(int(number))

    return f"{number:.3f}"


def format_score(value: Any) -> str:
    """Return a score rounded to three decimal places."""

    return f"{as_float(value):.3f}"


def get_rows(analysis_result: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a row list from the analysis result."""

    rows = analysis_result.get(key)

    if not isinstance(rows, list):
        return []

    return [
        row
        for row in rows
        if isinstance(row, dict)
    ]


def count_rows(rows: list[dict[str, Any]], field: str, value: Any) -> int:
    """Count rows where a field equals a value."""

    return len([
        row
        for row in rows
        if row.get(field) == value
    ])


def count_truthy(rows: list[dict[str, Any]], field: str) -> int:
    """Count rows where a field is truthy."""

    return len([
        row
        for row in rows
        if bool(row.get(field))
    ])


def find_aggregate_row(evaluation_rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the aggregate evaluation row when present."""

    for row in evaluation_rows:
        if row.get("EvaluationScope") == "aggregate":
            return row

    return {}


def find_scan_evaluation_rows(evaluation_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return scan-level evaluation rows."""

    return [
        row
        for row in evaluation_rows
        if row.get("EvaluationScope") == "scan"
    ]


def group_rows_by_scan_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group rows by ScanId."""

    grouped_rows: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        scan_id = text(row.get("ScanId"))

        if scan_id not in grouped_rows:
            grouped_rows[scan_id] = []

        grouped_rows[scan_id].append(row)

    return grouped_rows


def get_cpri_top_rows(ranking_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return CPRI top-ranked candidate rows."""

    return [
        row
        for row in ranking_rows
        if as_int(row.get("CPRIRank")) == 1
    ]


def get_candidate_count_by_scan(candidate_rows: list[dict[str, Any]]) -> dict[str, int]:
    """Return candidate counts grouped by ScanId."""

    grouped_rows = group_rows_by_scan_id(candidate_rows)

    return {
        scan_id: len(rows)
        for scan_id, rows in grouped_rows.items()
    }


def get_top_cpri_kb_by_scan(ranking_rows: list[dict[str, Any]]) -> dict[str, str]:
    """Return CPRI top KB grouped by ScanId."""

    return {
        text(row.get("ScanId")): text(row.get("KB"))
        for row in get_cpri_top_rows(ranking_rows)
    }


def get_largest_movement_rows(
    ranking_rows: list[dict[str, Any]],
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Return rows with the largest absolute CPRI movement."""

    moved_rows = [
        row
        for row in ranking_rows
        if (
            abs(as_int(row.get("CPRIvsCVSSRankDelta"))) > 0 or
            abs(as_int(row.get("CPRIvsMSRCRankDelta"))) > 0
        )
    ]

    return sorted(
        moved_rows,
        key=lambda row: (
            -max(
                abs(as_int(row.get("CPRIvsCVSSRankDelta"))),
                abs(as_int(row.get("CPRIvsMSRCRankDelta"))),
            ),
            as_int(row.get("ScanId")),
            text(row.get("KB")),
        ),
    )[:limit]


# ------------------------------------------------------------
# MARKDOWN HELPERS
# ------------------------------------------------------------

def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Build a Markdown table."""

    if not rows:
        return ""

    output: list[str] = []

    output.append("| " + " | ".join(headers) + " |")
    output.append("| " + " | ".join("---" for _ in headers) + " |")

    for row in rows:
        output.append("| " + " | ".join(text(value) for value in row) + " |")

    return "\n".join(output)


def write_section(lines: list[str], title: str) -> None:
    """Append a report section heading."""

    lines.append("")
    lines.append(f"## {title}")
    lines.append("")


def append_paragraph(lines: list[str], value: str) -> None:
    """Append a paragraph with spacing."""

    lines.append(value)
    lines.append("")


# ------------------------------------------------------------
# REPORT SECTIONS
# ------------------------------------------------------------

def append_analysis_outcome(
    lines: list[str],
    analysis_result: dict[str, Any],
    scan_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    enrichment_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append the opening analysis outcome section."""

    write_section(lines, "Analysis Outcome")

    aggregate_row = find_aggregate_row(evaluation_rows)

    append_paragraph(
        lines,
        "Remetria analysed Kolektria runtime evidence and produced a "
        "context-aware Windows patch remediation ranking. The run generated "
        "candidate, enrichment, ranking, evaluation and report outputs from the "
        "same in-memory analysis result.",
    )

    lines.append(markdown_table(
        headers=["Metric", "Value"],
        rows=[
            ["Result type", analysis_result.get("ResultType", "")],
            ["Generated UTC", analysis_result.get("GeneratedUtc", "")],
            ["Runtime scans", len(scan_rows)],
            ["Missing KB candidates", len(candidate_rows)],
            ["Unique CVEs enriched", len(enrichment_rows)],
            ["Ranking rows", len(ranking_rows)],
            ["Evaluation rows", len(evaluation_rows)],
            [
                "Candidate-bearing scans",
                aggregate_row.get("CandidateBearingScanCount", 0),
            ],
        ],
    ))


def append_runtime_dataset(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append a concise runtime dataset section."""

    write_section(lines, "Runtime Dataset")

    if not scan_rows:
        lines.append("No scan summary rows were produced.")
        return

    candidate_counts = get_candidate_count_by_scan(candidate_rows)
    top_cpri_by_scan = get_top_cpri_kb_by_scan(ranking_rows)

    append_paragraph(
        lines,
        "The runtime dataset contains the active Kolektria scan files selected "
        "for this Remetria run. Scan identifiers are assigned numerically for "
        "the analysis, while the source filename remains available for traceability.",
    )

    lines.append(markdown_table(
        headers=[
            "Scan",
            "Source",
            "OS",
            "LCU Month",
            "Patch Age",
            "Missing KBs",
            "Candidates",
            "CPRI Top KB",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                Path(text(row.get("SourcePath", ""))).name,
                f"{row.get('OsName', '')} {row.get('OsEdition', '')}".strip(),
                row.get("LcuMonthId", ""),
                row.get("PatchAgeDays", ""),
                row.get("MissingKbCount", ""),
                candidate_counts.get(text(row.get("ScanId")), 0),
                top_cpri_by_scan.get(text(row.get("ScanId")), "n/a"),
            ]
            for row in scan_rows
        ],
    ))


def append_candidate_set(
    lines: list[str],
    candidate_rows: list[dict[str, Any]],
) -> None:
    """Append candidate set summary."""

    write_section(lines, "Candidate Set")

    if not candidate_rows:
        append_paragraph(
            lines,
            "No missing KB remediation candidates were produced. Ranking and "
            "evaluation are not applicable for this runtime dataset.",
        )
        return

    grouped_rows = group_rows_by_scan_id(candidate_rows)

    append_paragraph(
        lines,
        "Remetria treats each missing KB as a remediation candidate. Candidate "
        "rows preserve the local patch context needed for CPRI ranking, including "
        "patch age, CVE volume, supersedence and runtime prevalence.",
    )

    lines.append(markdown_table(
        headers=[
            "Scan",
            "Candidate Count",
            "Largest Candidate CVE Count",
            "Repeated Missing KBs",
        ],
        rows=[
            [
                scan_id,
                len(rows),
                max(as_int(row.get("UniqueCveCount")) for row in rows),
                len([
                    row
                    for row in rows
                    if as_int(row.get("MissingInRuntimeScanCount")) > 1
                ]),
            ]
            for scan_id, rows in sorted(
                grouped_rows.items(),
                key=lambda item: as_int(item[0]),
            )
        ],
    ))


def append_enrichment_coverage(
    lines: list[str],
    enrichment_rows: list[dict[str, Any]],
) -> None:
    """Append enrichment coverage summary."""

    write_section(lines, "Enrichment Coverage")

    if not enrichment_rows:
        append_paragraph(lines, "No CVE enrichment rows were produced.")
        return

    resolved_count = count_rows(
        rows=enrichment_rows,
        field="EnrichmentStatus",
        value="resolved",
    )
    missing_count = len(enrichment_rows) - resolved_count

    append_paragraph(
        lines,
        "The enrichment stage used MSRC CVRF metadata to attach advisory and "
        "CVSS fields to the CVEs observed in the Kolektria evidence. These fields "
        "support CVSS-only, MSRC-only and CPRI ranking.",
    )

    lines.append(markdown_table(
        headers=["Metric", "Value"],
        rows=[
            ["Unique CVEs observed", len(enrichment_rows)],
            ["Resolved CVEs", resolved_count],
            ["Missing enrichment rows", missing_count],
            ["CVSS Critical", count_rows(enrichment_rows, "CvssSeverity", "CRITICAL")],
            ["CVSS High", count_rows(enrichment_rows, "CvssSeverity", "HIGH")],
            ["CVSS Medium", count_rows(enrichment_rows, "CvssSeverity", "MEDIUM")],
            ["CVSS Low", count_rows(enrichment_rows, "CvssSeverity", "LOW")],
            ["CVSS Unknown", count_rows(enrichment_rows, "CvssSeverity", "UNKNOWN")],
            ["MSRC known exploited", count_truthy(enrichment_rows, "MsrcKnownExploited")],
            [
                "MSRC publicly disclosed",
                count_truthy(enrichment_rows, "MsrcPubliclyDisclosed"),
            ],
        ],
    ))


def append_ranking_comparison(
    lines: list[str],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append ranking comparison summary."""

    write_section(lines, "Ranking Comparison")

    if not ranking_rows:
        append_paragraph(
            lines,
            "No ranking comparison rows were produced because no missing KB "
            "remediation candidates were available.",
        )
        return

    append_paragraph(
        lines,
        "Remetria compares three deterministic ranking methods. CVSS ranks "
        "candidates by CVSS-derived severity fields. MSRC ranks candidates by "
        "Microsoft advisory severity and advisory exploit/disclosure signals. "
        "CPRI is the proposed Contextual Patch Remediation Index, which combines "
        "external vulnerability metadata with local remediation context.",
    )

    top_rows = sorted(
        get_cpri_top_rows(ranking_rows),
        key=lambda row: as_int(row.get("ScanId")),
    )

    lines.append(markdown_table(
        headers=[
            "Scan",
            "CPRI Top KB",
            "CVSS Rank",
            "MSRC Rank",
            "CPRI Score",
            "Max CVSS",
            "Max MSRC Severity",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                row.get("KB", ""),
                row.get("CVSSRank", ""),
                row.get("MSRCRank", ""),
                format_score(row.get("CPRIScore")),
                row.get("MaxCvssBaseScore", ""),
                row.get("MaxMsrcSeverity", ""),
            ]
            for row in top_rows
        ],
    ))

    movement_rows = get_largest_movement_rows(ranking_rows)

    if not movement_rows:
        return

    lines.append("")
    lines.append("Largest observed CPRI rank movements:")
    lines.append("")
    lines.append(markdown_table(
        headers=[
            "Scan",
            "KB",
            "CVSS Rank",
            "MSRC Rank",
            "CPRI Rank",
            "CPRI vs CVSS",
            "CPRI vs MSRC",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                row.get("KB", ""),
                row.get("CVSSRank", ""),
                row.get("MSRCRank", ""),
                row.get("CPRIRank", ""),
                row.get("CPRIvsCVSSRankDelta", ""),
                row.get("CPRIvsMSRCRankDelta", ""),
            ]
            for row in movement_rows
        ],
    ))


def append_evaluation_metrics(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append evaluation metrics summary."""

    write_section(lines, "Evaluation Metrics")

    if not evaluation_rows:
        append_paragraph(lines, "No evaluation metrics were produced.")
        return

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        append_paragraph(lines, "Aggregate evaluation metrics were not produced.")
        return

    lines.append(markdown_table(
        headers=["Metric", "Value"],
        rows=[
            ["Candidate count", aggregate_row.get("CandidateCount", "")],
            [
                "Candidate-bearing scans",
                aggregate_row.get("CandidateBearingScanCount", ""),
            ],
            [
                "CPRI/CVSS top-1 match ratio",
                format_number(aggregate_row.get("CVSSTop1MatchRatio")),
            ],
            [
                "CPRI/MSRC top-1 match ratio",
                format_number(aggregate_row.get("MSRCTop1MatchRatio")),
            ],
            [
                "Average CVSS/CPRI top-N overlap",
                format_number(aggregate_row.get("CVSSCPRITopNOverlapRatio")),
            ],
            [
                "Average MSRC/CPRI top-N overlap",
                format_number(aggregate_row.get("MSRCCPRITopNOverlapRatio")),
            ],
            [
                "Average absolute movement vs CVSS",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsCVSSMovement")),
            ],
            [
                "Average absolute movement vs MSRC",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsMSRCMovement")),
            ],
            [
                "Maximum absolute movement vs CVSS",
                aggregate_row.get("MaxAbsoluteCPRIvsCVSSMovement", ""),
            ],
            [
                "Maximum absolute movement vs MSRC",
                aggregate_row.get("MaxAbsoluteCPRIvsMSRCMovement", ""),
            ],
        ],
    ))

    scan_rows = find_scan_evaluation_rows(evaluation_rows)

    if not scan_rows:
        return

    lines.append("")
    lines.append(markdown_table(
        headers=[
            "Scan",
            "Candidates",
            "CPRI Top KB",
            "Matches CVSS Top 1",
            "Matches MSRC Top 1",
            "Avg Abs Move vs CVSS",
            "Avg Abs Move vs MSRC",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                row.get("CandidateCount", ""),
                row.get("CPRITop1KB", ""),
                bool_label(row.get("CPRIMatchesCVSSTop1")),
                bool_label(row.get("CPRIMatchesMSRCTop1")),
                format_number(row.get("AverageAbsoluteCPRIvsCVSSMovement")),
                format_number(row.get("AverageAbsoluteCPRIvsMSRCMovement")),
            ]
            for row in scan_rows
        ],
    ))


def append_interpretation(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append controlled interpretation notes."""

    write_section(lines, "Interpretation")

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        append_paragraph(
            lines,
            "No aggregate ranking metrics were available. This usually means "
            "there were no missing KB remediation candidates in the runtime dataset.",
        )
        return

    append_paragraph(
        lines,
        "CVSS-only and MSRC-only rankings are used as baseline prioritisation "
        "methods, not ground truth labels. CPRI is the proposed context-aware "
        "ranking method for this Windows KB remediation workflow.",
    )

    append_paragraph(
        lines,
        "Where CPRI matches a baseline top-ranked KB, the context-aware method "
        "preserves that priority. Where CPRI changes candidate order, the movement "
        "is explained by the combination of local patch context and enriched "
        "advisory metadata.",
    )

    append_paragraph(
        lines,
        "Average signed movement can balance to zero because movement within a "
        "scan is directional. Average absolute movement is the more useful metric "
        "for describing how much the ranking order changed.",
    )


def append_limitations(lines: list[str]) -> None:
    """Append report limitations."""

    write_section(lines, "Limitations")

    lines.append(
        "- Remetria evaluates deterministic ranking behaviour. It does not provide "
        "supervised machine-learning accuracy because independent ground-truth "
        "remediation labels were not available."
    )
    lines.append(
        "- CVSS and MSRC severity are baseline ranking signals. They are not treated "
        "as proof that a candidate is the objectively correct remediation priority."
    )
    lines.append(
        "- CPRI is a lightweight context-aware remediation index for this project "
        "workflow. It is not presented as a replacement for established "
        "vulnerability prioritisation frameworks."
    )
    lines.append(
        "- Remetria does not perform exploit testing, vulnerability scanning, "
        "automatic patching, or production remediation."
    )
    lines.append(
        "- Ranking results depend on the Kolektria scan evidence and the MSRC CVRF "
        "metadata available during enrichment."
    )
    lines.append(
        "- Patch age contributes to local context, but in per-scan ranking it may "
        "be constant across candidates from the same host."
    )


# ------------------------------------------------------------
# REPORT WORKFLOW
# ------------------------------------------------------------

def build_markdown_report(analysis_result: dict[str, Any]) -> str:
    """Build the Remetria Markdown report content."""

    scan_rows = get_rows(analysis_result, "ScanSummaryRows")
    candidate_rows = get_rows(analysis_result, "KbCandidateRows")
    enrichment_rows = get_rows(analysis_result, "CveEnrichmentRows")
    ranking_rows = get_rows(analysis_result, "RankingComparisonRows")
    evaluation_rows = get_rows(analysis_result, "EvaluationMetricRows")

    lines: list[str] = []

    lines.append("# Remetria Analysis Report")
    lines.append("")

    append_analysis_outcome(
        lines=lines,
        analysis_result=analysis_result,
        scan_rows=scan_rows,
        candidate_rows=candidate_rows,
        enrichment_rows=enrichment_rows,
        ranking_rows=ranking_rows,
        evaluation_rows=evaluation_rows,
    )
    append_runtime_dataset(
        lines=lines,
        scan_rows=scan_rows,
        candidate_rows=candidate_rows,
        ranking_rows=ranking_rows,
    )
    append_candidate_set(lines, candidate_rows)
    append_enrichment_coverage(lines, enrichment_rows)
    append_ranking_comparison(lines, ranking_rows)
    append_evaluation_metrics(lines, evaluation_rows)
    append_interpretation(lines, evaluation_rows)
    append_limitations(lines)

    lines.append("")

    return "\n".join(lines)


def write_markdown_report(analysis_result: dict[str, Any]) -> Path:
    """Write the Remetria Markdown report."""

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    report_content = build_markdown_report(analysis_result)

    with REPORT_PATH.open("w", encoding="utf-8") as file:
        file.write(report_content)

    return REPORT_PATH