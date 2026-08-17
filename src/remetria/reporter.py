"""
Remetria Markdown reporter.

Writes a human-readable report from the current in-memory Remetria analysis
result. The report summarises scan intake, candidate generation, enrichment,
ranking comparison, evaluation metrics, and limitations.
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
    """Return Yes/No for boolean-like values."""

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


def get_rows(analysis_result: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return a row list from the analysis result."""

    rows = analysis_result.get(key)

    if isinstance(rows, list):
        return [
            row
            for row in rows
            if isinstance(row, dict)
        ]

    return []


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


# ------------------------------------------------------------
# SUMMARY SECTIONS
# ------------------------------------------------------------

def append_run_summary(lines: list[str], analysis_result: dict[str, Any]) -> None:
    """Append run summary details."""

    write_section(lines, "Run Summary")

    lines.append(markdown_table(
        headers=["Field", "Value"],
        rows=[
            ["Tool", analysis_result.get("Tool", "")],
            ["Result type", analysis_result.get("ResultType", "")],
            ["Generated UTC", analysis_result.get("GeneratedUtc", "")],
            ["Runtime scan count", analysis_result.get("RuntimeScanCount", "")],
            ["Scan IDs", "; ".join(analysis_result.get("ScanIds", []))],
        ],
    ))


def append_scan_summary(lines: list[str], scan_rows: list[dict[str, Any]]) -> None:
    """Append scan summary table."""

    write_section(lines, "Scan Summary")

    if not scan_rows:
        lines.append("No scan summary rows were produced.")
        return

    lines.append(markdown_table(
        headers=[
            "ScanId",
            "OS",
            "Version",
            "Build",
            "LCU Month",
            "Patch Age Days",
            "Installed KBs",
            "Missing KBs",
            "Unique CVEs",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                f"{row.get('OsName', '')} {row.get('OsEdition', '')}".strip(),
                row.get("DisplayVersion", ""),
                row.get("Build", ""),
                row.get("LcuMonthId", ""),
                row.get("PatchAgeDays", ""),
                row.get("InstalledKbCount", ""),
                row.get("MissingKbCount", ""),
                row.get("UniqueCveCount", ""),
            ]
            for row in scan_rows
        ],
    ))


def append_candidate_summary(
    lines: list[str],
    candidate_rows: list[dict[str, Any]],
) -> None:
    """Append candidate summary."""

    write_section(lines, "Candidate Summary")

    if not candidate_rows:
        lines.append("No missing KB remediation candidates were produced.")
        return

    lines.append(markdown_table(
        headers=[
            "ScanId",
            "KB",
            "Patch Age Days",
            "Unique CVEs",
            "Missing In Runtime Scans",
            "Supersedes Count",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                row.get("KB", ""),
                row.get("PatchAgeDays", ""),
                row.get("UniqueCveCount", ""),
                row.get("MissingInRuntimeScanCount", ""),
                row.get("SupersedesCount", ""),
            ]
            for row in candidate_rows
        ],
    ))


def append_enrichment_summary(
    lines: list[str],
    enrichment_rows: list[dict[str, Any]],
) -> None:
    """Append CVE enrichment summary."""

    write_section(lines, "Enrichment Summary")

    if not enrichment_rows:
        lines.append("No CVE enrichment rows were produced.")
        return

    resolved_count = len([
        row
        for row in enrichment_rows
        if row.get("EnrichmentStatus") == "resolved"
    ])
    missing_count = len(enrichment_rows) - resolved_count

    critical_count = len([
        row
        for row in enrichment_rows
        if row.get("CvssSeverity") == "CRITICAL"
    ])
    high_count = len([
        row
        for row in enrichment_rows
        if row.get("CvssSeverity") == "HIGH"
    ])
    medium_count = len([
        row
        for row in enrichment_rows
        if row.get("CvssSeverity") == "MEDIUM"
    ])
    low_count = len([
        row
        for row in enrichment_rows
        if row.get("CvssSeverity") == "LOW"
    ])
    unknown_count = len([
        row
        for row in enrichment_rows
        if row.get("CvssSeverity") == "UNKNOWN"
    ])
    known_exploited_count = len([
        row
        for row in enrichment_rows
        if bool(row.get("MsrcKnownExploited"))
    ])
    publicly_disclosed_count = len([
        row
        for row in enrichment_rows
        if bool(row.get("MsrcPubliclyDisclosed"))
    ])

    lines.append(markdown_table(
        headers=["Metric", "Value"],
        rows=[
            ["Unique CVEs enriched", len(enrichment_rows)],
            ["Resolved CVEs", resolved_count],
            ["Missing enrichment rows", missing_count],
            ["CVSS Critical CVEs", critical_count],
            ["CVSS High CVEs", high_count],
            ["CVSS Medium CVEs", medium_count],
            ["CVSS Low CVEs", low_count],
            ["CVSS Unknown CVEs", unknown_count],
            ["MSRC known exploited CVEs", known_exploited_count],
            ["MSRC publicly disclosed CVEs", publicly_disclosed_count],
        ],
    ))


def append_ranking_summary(
    lines: list[str],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append ranking comparison summary."""

    write_section(lines, "Ranking Summary")

    if not ranking_rows:
        lines.append(
            "No ranking comparison rows were produced because no missing KB "
            "remediation candidates were available."
        )
        return

    top_rows = [
        row
        for row in ranking_rows
        if as_int(row.get("CPRIRank")) == 1
    ]

    lines.append(markdown_table(
        headers=[
            "ScanId",
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
                format_number(row.get("CPRIScore")),
                row.get("MaxCvssBaseScore", ""),
                row.get("MaxMsrcSeverity", ""),
            ]
            for row in top_rows
        ],
    ))


def append_evaluation_summary(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append evaluation metrics summary."""

    write_section(lines, "Evaluation Summary")

    if not evaluation_rows:
        lines.append("No evaluation metrics were produced.")
        return

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        lines.append("Aggregate evaluation metrics were not produced.")
        return

    lines.append(markdown_table(
        headers=["Metric", "Value"],
        rows=[
            ["Candidate count", aggregate_row.get("CandidateCount", "")],
            [
                "Candidate-bearing scan count",
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
                "Average CVSS/CPRI top-N overlap ratio",
                format_number(aggregate_row.get("CVSSCPRITopNOverlapRatio")),
            ],
            [
                "Average MSRC/CPRI top-N overlap ratio",
                format_number(aggregate_row.get("MSRCCPRITopNOverlapRatio")),
            ],
            [
                "Average absolute CPRI vs CVSS movement",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsCVSSMovement")),
            ],
            [
                "Average absolute CPRI vs MSRC movement",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsMSRCMovement")),
            ],
            [
                "Maximum absolute CPRI vs CVSS movement",
                aggregate_row.get("MaxAbsoluteCPRIvsCVSSMovement", ""),
            ],
            [
                "Maximum absolute CPRI vs MSRC movement",
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
            "ScanId",
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


def append_interpretation(lines: list[str], evaluation_rows: list[dict[str, Any]]) -> None:
    """Append controlled interpretation notes."""

    write_section(lines, "Interpretation Notes")

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        lines.append(
            "No aggregate ranking metrics were available. This usually means "
            "there were no missing KB remediation candidates in the runtime dataset."
        )
        return

    lines.append(
        "CVSS-only and MSRC-only rankings are treated as baseline prioritisation "
        "methods, not ground truth labels. CPRI is the proposed context-aware "
        "ranking method."
    )
    lines.append("")
    lines.append(
        "Where CPRI matches a baseline top-ranked KB, the context-aware method "
        "preserves that priority. Where CPRI changes candidate order, the movement "
        "is explained by local remediation context and enriched advisory metadata."
    )
    lines.append("")
    lines.append(
        "Average signed movement can balance to zero because movement within a "
        "scan is directional. Average absolute movement is the more useful metric "
        "for describing the amount of ranking change."
    )


def append_limitations(lines: list[str]) -> None:
    """Append report limitations."""

    write_section(lines, "Limitations")

    lines.append(
        "- The workflow evaluates deterministic ranking behaviour. It does not "
        "provide supervised machine-learning accuracy because ground-truth "
        "remediation labels were not available."
    )
    lines.append(
        "- CVSS and MSRC severity are used as baseline ranking signals, not as proof "
        "that a candidate is the objectively correct remediation priority."
    )
    lines.append(
        "- The workflow does not perform exploit testing, vulnerability scanning, "
        "automatic patching, or production remediation."
    )
    lines.append(
        "- Ranking results depend on the available Kolektria scan evidence and the "
        "MSRC CVRF metadata available during enrichment."
    )
    lines.append(
        "- Patch age is useful for local context, but in per-scan ranking it may be "
        "constant across candidates from the same host."
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

    append_run_summary(lines, analysis_result)
    append_scan_summary(lines, scan_rows)
    append_candidate_summary(lines, candidate_rows)
    append_enrichment_summary(lines, enrichment_rows)
    append_ranking_summary(lines, ranking_rows)
    append_evaluation_summary(lines, evaluation_rows)
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