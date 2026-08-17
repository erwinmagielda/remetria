"""
Remetria Markdown reporter.

Writes a structured analysis report from the current in-memory Remetria result.
The report follows the same practical style as Kolektria: each section explains
its purpose before presenting evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# VALUE HELPERS
# ------------------------------------------------------------

def text(value: Any) -> str:
    """Return a clean string value."""

    if value is None:
        return ""

    return str(value)


def is_empty(value: Any) -> bool:
    """Return True when a value is empty."""

    return text(value).strip() == ""


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

    lowered_value = text(value).strip().lower()

    if lowered_value == "true":
        return "Yes"

    if lowered_value == "false":
        return "No"

    return text(value)


def format_number(value: Any) -> str:
    """Return a compact display number."""

    if is_empty(value):
        return ""

    number = as_float(value)

    if number.is_integer():
        return str(int(number))

    return f"{number:.3f}"


def format_decimal(value: Any, places: int = 3) -> str:
    """Return a decimal number with a fixed number of places."""

    if is_empty(value):
        return ""

    return f"{as_float(value):.{places}f}"


def source_name(source_path: Any) -> str:
    """Return a source filename from a project path."""

    value = text(source_path).replace("\\", "/")

    if not value:
        return ""

    return value.rsplit("/", maxsplit=1)[-1]


def escape_table_value(value: Any) -> str:
    """Escape a value for use inside a Markdown table."""

    return text(value).replace("\n", " ").replace("|", "\\|")


# ------------------------------------------------------------
# ROW HELPERS
# ------------------------------------------------------------

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


def scan_sort_key(value: Any) -> tuple[int, int | str]:
    """Return a stable sort key for numeric and non-numeric scan IDs."""

    scan_id = text(value)

    try:
        return (0, int(scan_id))
    except ValueError:
        return (1, scan_id)


def group_rows_by_scan_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group rows by ScanId."""

    grouped_rows: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        scan_id = text(row.get("ScanId"))

        if not scan_id:
            continue

        if scan_id not in grouped_rows:
            grouped_rows[scan_id] = []

        grouped_rows[scan_id].append(row)

    return grouped_rows


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


def find_scan_evaluation_rows(
    evaluation_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return scan-level evaluation rows."""

    return sorted(
        [
            row
            for row in evaluation_rows
            if row.get("EvaluationScope") == "scan"
        ],
        key=lambda row: scan_sort_key(row.get("ScanId")),
    )


def get_cpri_top_rows(ranking_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return CPRI top-ranked candidate rows."""

    return sorted(
        [
            row
            for row in ranking_rows
            if as_int(row.get("CPRIRank")) == 1
        ],
        key=lambda row: scan_sort_key(row.get("ScanId")),
    )


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
            scan_sort_key(row.get("ScanId")),
            text(row.get("KB")),
        ),
    )[:limit]


def get_scan_role(scan_row: dict[str, Any]) -> str:
    """Return a concise role label for a scan."""

    missing_count = as_int(scan_row.get("MissingKbCount"))
    patch_age = as_int(scan_row.get("PatchAgeDays"))

    if missing_count == 0:
        return "No-candidate control"

    if patch_age >= 180:
        return "Aged patch state"

    if patch_age >= 30:
        return "Older patch state"

    return "Recent patch state"


def get_candidate_note(scan_row: dict[str, Any], candidate_count: int) -> str:
    """Return a short candidate interpretation note."""

    if candidate_count == 0:
        return "No missing KB candidates were available for ranking."

    patch_age = as_int(scan_row.get("PatchAgeDays"))

    if patch_age >= 180:
        return "Large aged candidate set with extended remediation backlog."

    if patch_age >= 30:
        return "Older host state with multiple remediation candidates."

    return "Recent host state with limited missing update scope."


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
        output.append(
            "| " +
            " | ".join(escape_table_value(value) for value in row) +
            " |"
        )

    return "\n".join(output)


def add_heading(lines: list[str], title: str) -> None:
    """Append a second-level report heading."""

    lines.append("")
    lines.append(f"## {title}")
    lines.append("")


def add_paragraph(lines: list[str], value: str) -> None:
    """Append a paragraph."""

    lines.append(value)
    lines.append("")


def add_table(lines: list[str], headers: list[str], rows: list[list[Any]]) -> None:
    """Append a Markdown table with spacing."""

    table = markdown_table(headers, rows)

    if not table:
        return

    lines.append(table)
    lines.append("")


def add_bullets(lines: list[str], values: list[str]) -> None:
    """Append a bullet list."""

    for value in values:
        lines.append(f"- {value}")

    lines.append("")


# ------------------------------------------------------------
# REPORT SECTIONS
# ------------------------------------------------------------

def append_report_metadata(
    lines: list[str],
    analysis_result: dict[str, Any],
) -> None:
    """Append report metadata."""

    add_heading(lines, "Report Metadata")

    add_paragraph(
        lines,
        "This section identifies the Remetria analysis run and the output folder "
        "that contains the generated evidence package.",
    )

    add_table(
        lines=lines,
        headers=["Field", "Value", "Purpose"],
        rows=[
            [
                "Run ID",
                analysis_result.get("RunId", ""),
                "Timestamped identifier for this analysis output.",
            ],
            [
                "Generated UTC",
                analysis_result.get("GeneratedUtc", ""),
                "UTC timestamp used for report traceability.",
            ],
            [
                "Output root",
                analysis_result.get("OutputRoot", ""),
                "Folder containing the JSON, CSV and Markdown artefacts.",
            ],
            [
                "Result type",
                analysis_result.get("ResultType", ""),
                "Internal result label for this Remetria workflow.",
            ],
        ],
    )


def append_analysis_outcome(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    enrichment_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append the analysis outcome section."""

    add_heading(lines, "Analysis Outcome")

    aggregate_row = find_aggregate_row(evaluation_rows)
    candidate_bearing_scan_count = aggregate_row.get(
        "CandidateBearingScanCount",
        len(group_rows_by_scan_id(candidate_rows)),
    )

    add_paragraph(
        lines,
        "Remetria analysed the selected Kolektria runtime scans and produced "
        "Windows KB remediation ranking evidence. The workflow converted missing "
        "KBs into candidates, enriched observed CVEs, compared baseline rankings "
        "against CPRI, and exported evaluation metrics.",
    )

    add_table(
        lines=lines,
        headers=["Metric", "Value", "Meaning"],
        rows=[
            [
                "Runtime scans",
                len(scan_rows),
                "Kolektria JSON scans loaded from the active runtime input.",
            ],
            [
                "Candidate-bearing scans",
                candidate_bearing_scan_count,
                "Scans with at least one missing KB available for ranking.",
            ],
            [
                "Missing KB candidates",
                len(candidate_rows),
                "KB update candidates produced from missing update evidence.",
            ],
            [
                "Unique CVEs enriched",
                len(enrichment_rows),
                "Distinct CVEs resolved into MSRC/CVSS metadata rows.",
            ],
            [
                "Ranking rows",
                len(ranking_rows),
                "Candidate rows compared across CVSS, MSRC and CPRI methods.",
            ],
            [
                "Evaluation rows",
                len(evaluation_rows),
                "Scan-level and aggregate ranking comparison metrics.",
            ],
        ],
    )


def append_runtime_input(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append the runtime input section."""

    add_heading(lines, "Runtime Input")

    if not scan_rows:
        add_paragraph(lines, "No scan summary rows were produced.")
        return

    top_cpri_by_scan = get_top_cpri_kb_by_scan(ranking_rows)

    add_paragraph(
        lines,
        "This section summarises the Kolektria scan files selected for this "
        "analysis run. Remetria assigns numeric scan IDs for readable output, "
        "while the source path keeps each row traceable to the original JSON file.",
    )

    add_table(
        lines=lines,
        headers=[
            "Scan",
            "Source",
            "Windows State",
            "Build",
            "LCU Month",
            "Patch Age",
            "Missing KBs",
            "Role",
            "CPRI Top KB",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                source_name(row.get("SourcePath", "")),
                (
                    f"{row.get('OsName', '')} "
                    f"{row.get('DisplayVersion', '')}"
                ).strip(),
                row.get("Build", ""),
                row.get("LcuMonthId", ""),
                row.get("PatchAgeDays", ""),
                row.get("MissingKbCount", ""),
                get_scan_role(row),
                top_cpri_by_scan.get(text(row.get("ScanId")), "n/a"),
            ]
            for row in sorted(scan_rows, key=lambda row: scan_sort_key(row.get("ScanId")))
        ],
    )


def append_candidate_state(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
) -> None:
    """Append candidate state summary."""

    add_heading(lines, "Candidate State")

    add_paragraph(
        lines,
        "Remetria treats each missing KB as a remediation candidate. This section "
        "shows how candidate volume is distributed across the runtime scans before "
        "external severity and advisory metadata influence the ranking order.",
    )

    grouped_candidates = group_rows_by_scan_id(candidate_rows)

    table_rows: list[list[Any]] = []

    for scan_row in sorted(scan_rows, key=lambda row: scan_sort_key(row.get("ScanId"))):
        scan_id = text(scan_row.get("ScanId"))
        rows = grouped_candidates.get(scan_id, [])
        candidate_count = len(rows)

        if rows:
            largest_cve_set = max(as_int(row.get("UniqueCveCount")) for row in rows)
            repeated_candidates = len([
                row
                for row in rows
                if as_int(row.get("MissingInRuntimeScanCount")) > 1
            ])
        else:
            largest_cve_set = "n/a"
            repeated_candidates = 0

        table_rows.append([
            scan_id,
            candidate_count,
            largest_cve_set,
            repeated_candidates,
            get_candidate_note(scan_row, candidate_count),
        ])

    add_table(
        lines=lines,
        headers=[
            "Scan",
            "Candidates",
            "Largest CVE Set",
            "Repeated Candidates",
            "Interpretation",
        ],
        rows=table_rows,
    )


def append_enrichment_coverage(
    lines: list[str],
    enrichment_rows: list[dict[str, Any]],
) -> None:
    """Append enrichment coverage summary."""

    add_heading(lines, "Enrichment Coverage")

    if not enrichment_rows:
        add_paragraph(lines, "No CVE enrichment rows were produced.")
        return

    resolved_count = count_rows(
        rows=enrichment_rows,
        field="EnrichmentStatus",
        value="resolved",
    )
    missing_count = len(enrichment_rows) - resolved_count

    add_paragraph(
        lines,
        "The enrichment stage resolves observed CVEs into advisory and CVSS "
        "metadata. These fields support the baseline rankings and the CPRI "
        "calculation used later in the report.",
    )

    add_table(
        lines=lines,
        headers=["Metric", "Value", "Meaning"],
        rows=[
            [
                "Unique CVEs observed",
                len(enrichment_rows),
                "Distinct CVEs gathered from the runtime scan evidence.",
            ],
            [
                "Resolved CVEs",
                resolved_count,
                "CVE rows with enrichment metadata available.",
            ],
            [
                "Missing enrichment rows",
                missing_count,
                "CVE rows that could not be enriched during this run.",
            ],
            [
                "CVSS Critical",
                count_rows(enrichment_rows, "CvssSeverity", "CRITICAL"),
                "Resolved CVEs with critical CVSS severity.",
            ],
            [
                "CVSS High",
                count_rows(enrichment_rows, "CvssSeverity", "HIGH"),
                "Resolved CVEs with high CVSS severity.",
            ],
            [
                "CVSS Medium",
                count_rows(enrichment_rows, "CvssSeverity", "MEDIUM"),
                "Resolved CVEs with medium CVSS severity.",
            ],
            [
                "CVSS Low",
                count_rows(enrichment_rows, "CvssSeverity", "LOW"),
                "Resolved CVEs with low CVSS severity.",
            ],
            [
                "CVSS Unknown",
                count_rows(enrichment_rows, "CvssSeverity", "UNKNOWN"),
                "Resolved CVEs without a usable CVSS severity value.",
            ],
            [
                "MSRC known exploited",
                count_truthy(enrichment_rows, "MsrcKnownExploited"),
                "CVEs marked with known exploitation metadata.",
            ],
            [
                "MSRC publicly disclosed",
                count_truthy(enrichment_rows, "MsrcPubliclyDisclosed"),
                "CVEs marked with public disclosure metadata.",
            ],
        ],
    )


def append_ranking_method(lines: list[str]) -> None:
    """Append ranking method explanation."""

    add_heading(lines, "Ranking Method")

    add_paragraph(
        lines,
        "Remetria compares three deterministic ranking methods. CVSS-only and "
        "MSRC-only provide baseline views. CPRI, the Contextual Patch Remediation "
        "Index, combines enriched vulnerability metadata with local remediation "
        "context from the Kolektria scan evidence.",
    )

    add_table(
        lines=lines,
        headers=["Method", "Ranking Basis", "Role in Report"],
        rows=[
            [
                "CVSS-only",
                "Uses CVSS-derived severity and score fields.",
                "Severity baseline for comparing remediation order.",
            ],
            [
                "MSRC-only",
                "Uses Microsoft advisory severity and exploit/disclosure metadata.",
                "Advisory baseline for comparing remediation order.",
            ],
            [
                "CPRI",
                "Combines external vulnerability metadata with local KB context.",
                "Proposed context-aware remediation ranking.",
            ],
        ],
    )


def append_ranking_evidence(
    lines: list[str],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append ranking evidence section."""

    add_heading(lines, "Ranking Evidence")

    if not ranking_rows:
        add_paragraph(
            lines,
            "No ranking rows were produced because the runtime dataset did not "
            "contain missing KB remediation candidates.",
        )
        return

    add_paragraph(
        lines,
        "This section shows the highest-priority CPRI candidate for each "
        "candidate-bearing scan. The CVSS and MSRC rank columns show whether the "
        "same candidate was also prioritised by the baseline methods.",
    )

    add_table(
        lines=lines,
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
                format_decimal(row.get("CPRIScore")),
                row.get("MaxCvssBaseScore", ""),
                row.get("MaxMsrcSeverity", ""),
            ]
            for row in get_cpri_top_rows(ranking_rows)
        ],
    )

    movement_rows = get_largest_movement_rows(ranking_rows)

    if not movement_rows:
        add_paragraph(
            lines,
            "No CPRI rank movement was observed in this run. Candidate ordering "
            "matched the compared baseline ranks for all candidate-bearing scans.",
        )
        return

    add_paragraph(
        lines,
        "The next table lists the largest observed rank movements. The signed "
        "movement columns preserve direction from the ranking comparison output. "
        "The absolute size of the movement is the main indicator of how much the "
        "candidate order changed.",
    )

    add_table(
        lines=lines,
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
    )


def append_evaluation_metrics(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append evaluation metrics summary."""

    add_heading(lines, "Evaluation Metrics")

    if not evaluation_rows:
        add_paragraph(lines, "No evaluation metrics were produced.")
        return

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        add_paragraph(lines, "Aggregate evaluation metrics were not produced.")
        return

    add_paragraph(
        lines,
        "Evaluation metrics describe how CPRI compares with the two baseline "
        "methods. Top-1 agreement checks whether CPRI selected the same highest "
        "priority KB. Top-N overlap checks similarity across the upper-ranked "
        "candidate set. Absolute movement measures ranking change magnitude.",
    )

    add_table(
        lines=lines,
        headers=["Metric", "Value", "Meaning"],
        rows=[
            [
                "Candidate count",
                aggregate_row.get("CandidateCount", ""),
                "Total candidate rows included in ranking comparison.",
            ],
            [
                "Candidate-bearing scans",
                aggregate_row.get("CandidateBearingScanCount", ""),
                "Scans with at least one ranked candidate.",
            ],
            [
                "CPRI/CVSS top-1 match ratio",
                format_decimal(aggregate_row.get("CVSSTop1MatchRatio")),
                "Share of scans where CPRI and CVSS selected the same top KB.",
            ],
            [
                "CPRI/MSRC top-1 match ratio",
                format_decimal(aggregate_row.get("MSRCTop1MatchRatio")),
                "Share of scans where CPRI and MSRC selected the same top KB.",
            ],
            [
                "Average CVSS/CPRI top-N overlap",
                format_decimal(aggregate_row.get("CVSSCPRITopNOverlapRatio")),
                "Average upper-rank overlap between CVSS and CPRI.",
            ],
            [
                "Average MSRC/CPRI top-N overlap",
                format_decimal(aggregate_row.get("MSRCCPRITopNOverlapRatio")),
                "Average upper-rank overlap between MSRC and CPRI.",
            ],
            [
                "Average absolute movement vs CVSS",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsCVSSMovement")),
                "Average rank movement magnitude compared with CVSS.",
            ],
            [
                "Average absolute movement vs MSRC",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsMSRCMovement")),
                "Average rank movement magnitude compared with MSRC.",
            ],
            [
                "Maximum absolute movement vs CVSS",
                aggregate_row.get("MaxAbsoluteCPRIvsCVSSMovement", ""),
                "Largest candidate movement compared with CVSS.",
            ],
            [
                "Maximum absolute movement vs MSRC",
                aggregate_row.get("MaxAbsoluteCPRIvsMSRCMovement", ""),
                "Largest candidate movement compared with MSRC.",
            ],
        ],
    )

    scan_rows = find_scan_evaluation_rows(evaluation_rows)

    if not scan_rows:
        return

    add_paragraph(
        lines,
        "The scan-level view shows where CPRI agreed with the baseline top-ranked "
        "KB and where local context changed the ordering.",
    )

    add_table(
        lines=lines,
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
    )


def append_interpretation(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append controlled interpretation notes."""

    add_heading(lines, "Interpretation")

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        add_paragraph(
            lines,
            "No aggregate ranking metrics were available. This usually indicates "
            "that the runtime dataset did not contain missing KB remediation "
            "candidates.",
        )
        return

    cvss_top1 = as_float(aggregate_row.get("CVSSTop1MatchRatio"))
    msrc_top1 = as_float(aggregate_row.get("MSRCTop1MatchRatio"))
    cvss_movement = as_float(aggregate_row.get("AverageAbsoluteCPRIvsCVSSMovement"))
    msrc_movement = as_float(aggregate_row.get("AverageAbsoluteCPRIvsMSRCMovement"))

    interpretation_points: list[str] = []

    if cvss_top1 == 1.0:
        interpretation_points.append(
            "CPRI selected the same top KB as CVSS-only in every candidate-bearing "
            "scan, so the context-aware method preserved the strongest CVSS-led "
            "priority in this dataset."
        )
    elif cvss_top1 > 0:
        interpretation_points.append(
            "CPRI matched the CVSS-only top KB in some candidate-bearing scans and "
            "changed the top candidate in others."
        )
    else:
        interpretation_points.append(
            "CPRI did not select the same top KB as CVSS-only in the candidate-bearing "
            "scans from this run."
        )

    if msrc_top1 < cvss_top1:
        interpretation_points.append(
            "CPRI diverged more from MSRC-only top-1 ranking than from CVSS-only "
            "top-1 ranking in this run."
        )
    elif msrc_top1 == cvss_top1:
        interpretation_points.append(
            "CPRI showed the same top-1 agreement level with CVSS-only and MSRC-only "
            "ranking in this run."
        )
    else:
        interpretation_points.append(
            "CPRI showed stronger top-1 agreement with MSRC-only ranking than with "
            "CVSS-only ranking in this run."
        )

    if cvss_movement > 0 or msrc_movement > 0:
        interpretation_points.append(
            "Rank movement was present below the top candidate level. Average "
            "absolute movement is the clearest measure because signed movements "
            "can cancel each other within the same scan."
        )
    else:
        interpretation_points.append(
            "No average absolute rank movement was observed against the compared "
            "baselines in this run."
        )

    add_bullets(lines, interpretation_points)


def append_method(lines: list[str]) -> None:
    """Append method notes."""

    add_heading(lines, "Method")

    add_paragraph(
        lines,
        "Remetria uses Kolektria scan output as its input evidence. The analysis "
        "workflow keeps collection, enrichment, ranking and export steps separate "
        "so each stage can be reviewed independently.",
    )

    add_bullets(
        lines,
        [
            "Load selected Kolektria JSON scans from the active runtime directory.",
            "Normalise baseline, KB and CVE evidence into tabular row sets.",
            "Convert missing KBs into remediation candidate rows.",
            "Enrich observed CVEs with advisory and CVSS metadata.",
            "Rank candidates using CVSS-only, MSRC-only and CPRI methods.",
            "Export JSON, CSV tables and this Markdown report into one timestamped analysis folder.",
        ],
    )


def append_scope_notes(lines: list[str]) -> None:
    """Append scope notes."""

    add_heading(lines, "Scope Notes")

    add_paragraph(
        lines,
        "These notes define the boundaries of the Remetria analysis output and "
        "support correct interpretation of the evidence.",
    )

    add_bullets(
        lines,
        [
            "The report evaluates deterministic ranking behaviour.",
            "CVSS-only and MSRC-only rankings are comparison baselines, not ground-truth remediation labels.",
            "CPRI is the Contextual Patch Remediation Index used by this project workflow.",
            "The tool performs analysis and reporting. Vulnerability scanning, exploit testing, patch installation and production remediation execution are outside this workflow.",
            "Ranking results depend on the Kolektria scan evidence and the enrichment metadata available for the analysed CVEs.",
            "Patch age contributes to local context, but it can be constant across candidates from the same host.",
        ],
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
    lines.append(
        "Remetria is a Windows patch-remediation analysis tool. It consumes "
        "Kolektria scan evidence, enriches observed CVEs with advisory and CVSS "
        "metadata, ranks missing KB candidates using CVSS-only, MSRC-only and "
        "CPRI methods, and exports comparison evidence for dissertation evaluation."
    )
    lines.append("")

    append_report_metadata(lines, analysis_result)
    append_analysis_outcome(
        lines=lines,
        scan_rows=scan_rows,
        candidate_rows=candidate_rows,
        enrichment_rows=enrichment_rows,
        ranking_rows=ranking_rows,
        evaluation_rows=evaluation_rows,
    )
    append_runtime_input(lines, scan_rows, ranking_rows)
    append_candidate_state(lines, scan_rows, candidate_rows)
    append_enrichment_coverage(lines, enrichment_rows)
    append_ranking_method(lines)
    append_ranking_evidence(lines, ranking_rows)
    append_evaluation_metrics(lines, evaluation_rows)
    append_interpretation(lines, evaluation_rows)
    append_method(lines)
    append_scope_notes(lines)

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(
    analysis_result: dict[str, Any],
    report_path: Path,
) -> Path:
    """Write the Remetria Markdown report."""

    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_content = build_markdown_report(analysis_result)

    with report_path.open("w", encoding="utf-8") as file:
        file.write(report_content)

    return report_path