"""
Remetria Markdown reporter.

Writes a structured analysis report from the current in-memory Remetria result.
The report documents the analysis path, evidence transformation, ranking output
and evaluation metrics without relying on bullet-heavy summaries.
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


def format_number(value: Any) -> str:
    """Return a compact display number."""

    if text(value).strip() == "":
        return ""

    number = as_float(value)

    if number.is_integer():
        return str(int(number))

    return f"{number:.3f}"


def format_decimal(value: Any, places: int = 3) -> str:
    """Return a decimal number with a fixed number of places."""

    if text(value).strip() == "":
        return ""

    return f"{as_float(value):.{places}f}"


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


def code(value: Any) -> str:
    """Return a Markdown inline-code value."""

    clean_value = text(value)

    if clean_value.strip() == "":
        return ""

    return f"`{clean_value}`"


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


def find_scan_row(
    scan_rows: list[dict[str, Any]],
    scan_id: str,
) -> dict[str, Any]:
    """Return one scan summary row."""

    for row in scan_rows:
        if text(row.get("ScanId")) == scan_id:
            return row

    return {}


def get_candidate_bearing_scan_count(
    candidate_rows: list[dict[str, Any]],
) -> int:
    """Return number of scans with at least one candidate."""

    return len(group_rows_by_scan_id(candidate_rows))


def get_largest_candidate_cve_count(
    candidate_rows: list[dict[str, Any]],
) -> int:
    """Return the largest candidate CVE count."""

    if not candidate_rows:
        return 0

    return max(as_int(row.get("UniqueCveCount")) for row in candidate_rows)


def get_repeated_candidate_count(
    candidate_rows: list[dict[str, Any]],
) -> int:
    """Return the number of candidate rows repeated across runtime scans."""

    return len([
        row
        for row in candidate_rows
        if as_int(row.get("MissingInRuntimeScanCount")) > 1
    ])


def get_candidate_kb_count(
    candidate_rows: list[dict[str, Any]],
) -> int:
    """Return the number of unique candidate KBs."""

    return len({
        row.get("KB")
        for row in candidate_rows
        if row.get("KB")
    })


def get_top_cpri_kb_by_scan(ranking_rows: list[dict[str, Any]]) -> dict[str, str]:
    """Return the CPRI top KB grouped by ScanId."""

    top_rows: dict[str, str] = {}

    for row in ranking_rows:
        if as_int(row.get("CPRIRank")) == 1:
            top_rows[text(row.get("ScanId"))] = text(row.get("KB"))

    return top_rows


def get_missing_enrichment_count(enrichment_rows: list[dict[str, Any]]) -> int:
    """Return the number of unresolved enrichment rows."""

    return len([
        row
        for row in enrichment_rows
        if row.get("EnrichmentStatus") != "resolved"
    ])


# ------------------------------------------------------------
# INTERPRETATION HELPERS
# ------------------------------------------------------------

def get_scan_role(scan_row: dict[str, Any]) -> str:
    """Return a concise role label for a scan."""

    missing_count = as_int(scan_row.get("MissingKbCount"))
    patch_age = as_int(scan_row.get("PatchAgeDays"))

    if missing_count == 0:
        return "No-Candidate Control"

    if patch_age >= 180:
        return "Aged Patch State"

    if patch_age >= 30:
        return "Older Patch State"

    return "Recent Patch State"


def get_runtime_input_description(scan_row: dict[str, Any]) -> str:
    """Return a runtime input description."""

    missing_count = as_int(scan_row.get("MissingKbCount"))

    if missing_count == 0:
        return "Provides a clean comparison point with no missing KB candidates."

    return "Provides missing KB evidence for candidate ranking."


def get_rank_note(row: dict[str, Any]) -> str:
    """Return a short ranking note for one candidate row."""

    cvss_rank = as_int(row.get("CVSSRank"))
    msrc_rank = as_int(row.get("MSRCRank"))
    cpri_rank = as_int(row.get("CPRIRank"))

    if cpri_rank == 1 and cvss_rank == 1 and msrc_rank == 1:
        return "CPRI preserved both baseline top priorities."

    if cpri_rank == 1 and cvss_rank == 1:
        return "CPRI preserved the CVSS-only top priority while MSRC-only ranked it lower."

    if cpri_rank == 1 and msrc_rank == 1:
        return "CPRI preserved the MSRC-only top priority while CVSS-only ranked it lower."

    if cpri_rank == 1:
        return "CPRI selected this as the top candidate after applying local context."

    cvss_delta = as_int(row.get("CPRIvsCVSSRankDelta"))
    msrc_delta = as_int(row.get("CPRIvsMSRCRankDelta"))

    if cvss_delta == 0 and msrc_delta == 0:
        return "Candidate position matched both baseline ranks."

    if abs(cvss_delta) >= abs(msrc_delta):
        return "Candidate position changed mainly against the CVSS-only baseline."

    return "Candidate position changed mainly against the MSRC-only baseline."


def get_aggregate_interpretation(aggregate_row: dict[str, Any]) -> str:
    """Return aggregate interpretation paragraph."""

    cvss_agreement = as_float(aggregate_row.get("CVSSTop1MatchRatio"))
    msrc_agreement = as_float(aggregate_row.get("MSRCTop1MatchRatio"))

    if cvss_agreement == 1.0 and msrc_agreement < cvss_agreement:
        return (
            "CPRI selected the same top-ranked KB as CVSS-only in every "
            "candidate-bearing scan, while diverging more clearly from MSRC-only "
            "top-ranked selection. This means the context-aware method preserved "
            "high CVSS-led priority where it remained strongest, but still changed "
            "parts of the ordering when local and advisory context affected "
            "candidate placement."
        )

    if cvss_agreement > msrc_agreement:
        return (
            "CPRI showed stronger top-ranked KB agreement with CVSS-only than with "
            "MSRC-only in this run. The movement metrics describe how much the "
            "candidate order changed beyond the top-ranked KB."
        )

    if msrc_agreement > cvss_agreement:
        return (
            "CPRI showed stronger top-ranked KB agreement with MSRC-only than with "
            "CVSS-only in this run. The movement metrics describe how much the "
            "candidate order changed beyond the top-ranked KB."
        )

    return (
        "CPRI showed the same top-ranked KB agreement level with both baselines "
        "in this run. Absolute movement remains the main measure for lower-rank "
        "ordering changes."
    )


# ------------------------------------------------------------
# MARKDOWN HELPERS
# ------------------------------------------------------------

def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Build a left-aligned Markdown table."""

    if not rows:
        return ""

    output: list[str] = []

    output.append("| " + " | ".join(headers) + " |")
    output.append("| " + " | ".join(":---" for _ in headers) + " |")

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


def add_subheading(lines: list[str], title: str) -> None:
    """Append a third-level report heading."""

    lines.append("")
    lines.append(f"### {title}")
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
    """Append analysis outcome section."""

    add_heading(lines, "Analysis Outcome")

    add_paragraph(
        lines,
        "High-level result from this Remetria analysis run.",
    )

    aggregate_row = find_aggregate_row(evaluation_rows)

    add_table(
        lines=lines,
        headers=["Analysis Field", "Value", "Description"],
        rows=[
            [
                "Run ID",
                code(analysis_result.get("RunId", "")),
                "Timestamped identifier for this analysis package.",
            ],
            [
                "Generated UTC",
                analysis_result.get("GeneratedUtc", ""),
                "UTC timestamp for the generated report and output files.",
            ],
            [
                "Runtime Scans",
                len(scan_rows),
                "Kolektria JSON files loaded from the runtime input folder.",
            ],
            [
                "Candidate-Bearing Scans",
                aggregate_row.get(
                    "CandidateBearingScanCount",
                    get_candidate_bearing_scan_count(candidate_rows),
                ),
                "Scans with at least one missing KB available for ranking.",
            ],
            [
                "Missing KB Candidates",
                len(candidate_rows),
                "KB remediation candidates created from missing update evidence.",
            ],
            [
                "Unique CVEs Enriched",
                len(enrichment_rows),
                "Distinct CVEs resolved into enrichment metadata rows.",
            ],
            [
                "Ranking Rows",
                len(ranking_rows),
                "Candidate rows compared across CVSS-only, MSRC-only and CPRI.",
            ],
            [
                "Evaluation Rows",
                len(evaluation_rows),
                "Scan-level and aggregate comparison metrics.",
            ],
        ],
    )


def append_path_references(
    lines: list[str],
    analysis_result: dict[str, Any],
) -> None:
    """Append path reference section."""

    add_heading(lines, "Path References")

    add_paragraph(
        lines,
        "Paths used by this run are recorded so the generated JSON, CSV tables "
        "and Markdown report can be paired with the runtime evidence used for "
        "the analysis.",
    )

    output_paths = analysis_result.get("OutputPaths", {})

    if not isinstance(output_paths, dict):
        output_paths = {}

    add_table(
        lines=lines,
        headers=["Path Field", "Recorded Path", "Description"],
        rows=[
            [
                "Runtime Input",
                code(analysis_result.get("RuntimeInput", "")),
                "Folder containing the Kolektria scan JSON files selected for analysis.",
            ],
            [
                "Output Root",
                code(analysis_result.get("OutputRoot", "")),
                "Timestamped folder containing all generated Remetria artefacts.",
            ],
            [
                "Analysis JSON",
                code(output_paths.get("JsonPath", "")),
                "Machine-readable full analysis result.",
            ],
            [
                "CSV Tables",
                code(output_paths.get("TablesDir", "")),
                "Tabular outputs used for checking and dissertation evidence.",
            ],
            [
                "Markdown Report",
                code(output_paths.get("ReportPath", "")),
                "Readable report generated from the same analysis result.",
            ],
        ],
    )


def append_runtime_input(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append runtime input section."""

    add_heading(lines, "Runtime Input")

    add_paragraph(
        lines,
        "Kolektria scan evidence selected for this Remetria run.",
    )

    top_cpri_by_scan = get_top_cpri_kb_by_scan(ranking_rows)

    add_table(
        lines=lines,
        headers=[
            "Scan",
            "Source File",
            "Windows State",
            "Build",
            "LCU Month",
            "Patch Age",
            "Missing KBs",
            "Analysis Role",
            "Description",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                code(source_name(row.get("SourcePath", ""))),
                (
                    f"{row.get('OsName', '')} "
                    f"{row.get('DisplayVersion', '')}"
                ).strip(),
                code(row.get("Build", "")),
                code(row.get("LcuMonthId", "")),
                row.get("PatchAgeDays", ""),
                row.get("MissingKbCount", ""),
                get_scan_role(row),
                get_runtime_input_description(row),
            ]
            for row in sorted(scan_rows, key=lambda row: scan_sort_key(row.get("ScanId")))
        ],
    )

    if top_cpri_by_scan:
        add_paragraph(
            lines,
            "Scans without a CPRI top-ranked KB did not contain missing KB "
            "candidates and were therefore excluded from candidate ranking.",
        )


def append_evidence_normalisation(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    cve_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
) -> None:
    """Append evidence normalisation section."""

    add_heading(lines, "Evidence Normalisation")

    add_paragraph(
        lines,
        "Rows created from the Kolektria JSON evidence before enrichment and ranking.",
    )

    add_table(
        lines=lines,
        headers=["Evidence Row Set", "Rows", "Description"],
        rows=[
            [
                "Scan Summary Rows",
                len(scan_rows),
                "One summary row per loaded Kolektria scan.",
            ],
            [
                "CVE Evidence Rows",
                len(cve_rows),
                "Observed KB-to-CVE relationships expanded from scan evidence.",
            ],
            [
                "Candidate Rows",
                len(candidate_rows),
                "Missing KBs converted into remediation candidates.",
            ],
        ],
    )


def append_candidate_analysis(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
) -> None:
    """Append candidate analysis section."""

    add_heading(lines, "Candidate Analysis")

    add_paragraph(
        lines,
        "Breakdown of how missing KB evidence became remediation candidates.",
    )

    add_table(
        lines=lines,
        headers=["Candidate Field", "Value", "Explanation"],
        rows=[
            [
                "Runtime Scans",
                len(scan_rows),
                "Loaded Kolektria scans considered by this analysis run.",
            ],
            [
                "Candidate-Bearing Scans",
                get_candidate_bearing_scan_count(candidate_rows),
                "Scans with at least one missing KB available for ranking.",
            ],
            [
                "Candidate Rows",
                len(candidate_rows),
                "Missing KB instances ranked by Remetria.",
            ],
            [
                "Unique Candidate KBs",
                get_candidate_kb_count(candidate_rows),
                "Distinct KB identifiers across the runtime candidate set.",
            ],
            [
                "Largest Candidate CVE Set",
                get_largest_candidate_cve_count(candidate_rows),
                "Largest number of unique CVEs mapped to one missing KB candidate.",
            ],
            [
                "Repeated Candidate Rows",
                get_repeated_candidate_count(candidate_rows),
                "Candidate rows where the missing KB appeared across multiple runtime scans.",
            ],
        ],
    )


def append_cve_enrichment(
    lines: list[str],
    enrichment_rows: list[dict[str, Any]],
) -> None:
    """Append CVE enrichment section."""

    add_heading(lines, "CVE Enrichment")

    add_paragraph(
        lines,
        "Observed CVEs resolved into metadata used by the baseline and CPRI ranking methods.",
    )

    add_table(
        lines=lines,
        headers=["Enrichment Field", "Value", "Meaning"],
        rows=[
            [
                "Unique CVEs Observed",
                len(enrichment_rows),
                "Distinct CVEs gathered from the runtime scan evidence.",
            ],
            [
                "Resolved CVEs",
                count_rows(enrichment_rows, "EnrichmentStatus", "resolved"),
                "CVE rows with usable enrichment metadata.",
            ],
            [
                "Missing Enrichment Rows",
                get_missing_enrichment_count(enrichment_rows),
                "CVE rows not resolved during enrichment.",
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
                "MSRC Known Exploited",
                count_truthy(enrichment_rows, "MsrcKnownExploited"),
                "CVEs marked with known exploitation metadata.",
            ],
            [
                "MSRC Publicly Disclosed",
                count_truthy(enrichment_rows, "MsrcPubliclyDisclosed"),
                "CVEs marked with public disclosure metadata.",
            ],
        ],
    )


def append_ranking_method(lines: list[str]) -> None:
    """Append ranking method section."""

    add_heading(lines, "Ranking Method")

    add_paragraph(
        lines,
        "Ranking methods applied to each missing KB candidate.",
    )

    add_table(
        lines=lines,
        headers=["Method", "Basis", "Description"],
        rows=[
            [
                "CVSS-only",
                "CVSS-derived score and severity fields.",
                "Severity baseline used to compare candidate order.",
            ],
            [
                "MSRC-only",
                "Microsoft advisory severity and exploit/disclosure metadata.",
                "Advisory baseline used to compare candidate order.",
            ],
            [
                "CPRI",
                "Contextual Patch Remediation Index.",
                "Context-aware method combining enriched metadata with local KB remediation context.",
            ],
        ],
    )


def append_ranking_evidence(
    lines: list[str],
    scan_rows: list[dict[str, Any]],
    ranking_rows: list[dict[str, Any]],
) -> None:
    """Append ranking evidence section."""

    add_heading(lines, "Ranking Evidence")

    add_paragraph(
        lines,
        "Each candidate-bearing scan is shown as a separate evidence block. "
        "This keeps ranking evidence readable and preserves the relationship "
        "between the source scan, the candidate set and the ranking result.",
    )

    grouped_ranking_rows = group_rows_by_scan_id(ranking_rows)

    if not grouped_ranking_rows:
        add_paragraph(
            lines,
            "No ranking rows were produced because the runtime dataset did not "
            "contain missing KB remediation candidates.",
        )
        return

    for index, scan_id in enumerate(
        sorted(grouped_ranking_rows, key=scan_sort_key),
        start=1,
    ):
        scan_row = find_scan_row(scan_rows, scan_id)
        scan_ranking_rows = sorted(
            grouped_ranking_rows[scan_id],
            key=lambda row: as_int(row.get("CPRIRank")),
        )

        add_subheading(lines, f"{index}. Scan {scan_id}")

        add_table(
            lines=lines,
            headers=["Scan Field", "Recorded Value"],
            rows=[
                ["Source File", code(source_name(scan_row.get("SourcePath", "")))],
                [
                    "Windows State",
                    (
                        f"{scan_row.get('OsName', '')} "
                        f"{scan_row.get('DisplayVersion', '')}"
                    ).strip(),
                ],
                ["Build", code(scan_row.get("Build", ""))],
                ["LCU Month", code(scan_row.get("LcuMonthId", ""))],
                ["Patch Age Days", scan_row.get("PatchAgeDays", "")],
                ["Missing KBs", scan_row.get("MissingKbCount", "")],
                ["Analysis Role", get_scan_role(scan_row)],
            ],
        )

        add_paragraph(
            lines,
            "Candidate ranking for this scan. Lower rank numbers indicate higher "
            "priority within the selected method.",
        )

        add_table(
            lines=lines,
            headers=[
                "KB",
                "CVSS-only Rank",
                "MSRC-only Rank",
                "CPRI Rank",
                "CPRI Score",
                "Max CVSS",
                "Max MSRC Severity",
                "Ranking Note",
            ],
            rows=[
                [
                    code(row.get("KB", "")),
                    row.get("CVSSRank", ""),
                    row.get("MSRCRank", ""),
                    row.get("CPRIRank", ""),
                    format_decimal(row.get("CPRIScore")),
                    row.get("MaxCvssBaseScore", ""),
                    row.get("MaxMsrcSeverity", ""),
                    get_rank_note(row),
                ]
                for row in scan_ranking_rows
            ],
        )


def append_evaluation_metrics(
    lines: list[str],
    evaluation_rows: list[dict[str, Any]],
) -> None:
    """Append evaluation metrics section."""

    add_heading(lines, "Evaluation Metrics")

    add_paragraph(
        lines,
        "Ranking comparison metrics used to describe how CPRI agreed with or moved away from the baselines.",
    )

    aggregate_row = find_aggregate_row(evaluation_rows)

    if not aggregate_row:
        add_paragraph(lines, "Aggregate evaluation metrics were not produced.")
        return

    add_table(
        lines=lines,
        headers=["Metric", "Value", "Meaning"],
        rows=[
            [
                "Candidate Count",
                aggregate_row.get("CandidateCount", ""),
                "Total candidate rows included in ranking comparison.",
            ],
            [
                "Candidate-Bearing Scans",
                aggregate_row.get("CandidateBearingScanCount", ""),
                "Scans with at least one ranked candidate.",
            ],
            [
                "CPRI/CVSS Top-Ranked KB Agreement",
                format_decimal(aggregate_row.get("CVSSTop1MatchRatio")),
                "Share of scans where CPRI and CVSS-only selected the same top-ranked KB.",
            ],
            [
                "CPRI/MSRC Top-Ranked KB Agreement",
                format_decimal(aggregate_row.get("MSRCTop1MatchRatio")),
                "Share of scans where CPRI and MSRC-only selected the same top-ranked KB.",
            ],
            [
                "Average CVSS/CPRI Top-N Overlap",
                format_decimal(aggregate_row.get("CVSSCPRITopNOverlapRatio")),
                "Average upper-rank overlap between CVSS-only and CPRI.",
            ],
            [
                "Average MSRC/CPRI Top-N Overlap",
                format_decimal(aggregate_row.get("MSRCCPRITopNOverlapRatio")),
                "Average upper-rank overlap between MSRC-only and CPRI.",
            ],
            [
                "Average Absolute Movement vs CVSS",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsCVSSMovement")),
                "Average rank movement magnitude compared with CVSS-only.",
            ],
            [
                "Average Absolute Movement vs MSRC",
                format_number(aggregate_row.get("AverageAbsoluteCPRIvsMSRCMovement")),
                "Average rank movement magnitude compared with MSRC-only.",
            ],
            [
                "Maximum Absolute Movement vs CVSS",
                aggregate_row.get("MaxAbsoluteCPRIvsCVSSMovement", ""),
                "Largest candidate movement compared with CVSS-only.",
            ],
            [
                "Maximum Absolute Movement vs MSRC",
                aggregate_row.get("MaxAbsoluteCPRIvsMSRCMovement", ""),
                "Largest candidate movement compared with MSRC-only.",
            ],
        ],
    )

    add_paragraph(
        lines,
        get_aggregate_interpretation(aggregate_row),
    )

    scan_evaluation_rows = find_scan_evaluation_rows(evaluation_rows)

    if not scan_evaluation_rows:
        return

    add_paragraph(
        lines,
        "Scan-level metrics show where CPRI preserved a baseline top-ranked KB "
        "and where local context changed the ranking order.",
    )

    add_table(
        lines=lines,
        headers=[
            "Scan",
            "Candidates",
            "CPRI Top-Ranked KB",
            "Matches CVSS Top-Ranked KB",
            "Matches MSRC Top-Ranked KB",
            "Avg Abs Move vs CVSS",
            "Avg Abs Move vs MSRC",
        ],
        rows=[
            [
                row.get("ScanId", ""),
                row.get("CandidateCount", ""),
                code(row.get("CPRITop1KB", "")),
                bool_label(row.get("CPRIMatchesCVSSTop1")),
                bool_label(row.get("CPRIMatchesMSRCTop1")),
                format_number(row.get("AverageAbsoluteCPRIvsCVSSMovement")),
                format_number(row.get("AverageAbsoluteCPRIvsMSRCMovement")),
            ]
            for row in scan_evaluation_rows
        ],
    )


def append_method(lines: list[str]) -> None:
    """Append method section."""

    add_heading(lines, "Method")

    add_paragraph(
        lines,
        "Remetria loads selected Kolektria JSON scans from the active runtime "
        "input folder. It normalises scan summary fields and KB-to-CVE evidence "
        "into tabular row sets, then converts missing KBs into remediation "
        "candidate rows."
    )

    add_paragraph(
        lines,
        "Observed CVEs are enriched with advisory and CVSS metadata. The enriched "
        "candidate set is ranked through CVSS-only, MSRC-only and CPRI methods. "
        "The resulting ranking rows are evaluated through top-ranked KB agreement, "
        "top-N overlap and absolute rank movement metrics."
    )

    add_paragraph(
        lines,
        "The JSON, CSV and Markdown outputs are written into one timestamped "
        "analysis folder so each analysis run can be reviewed as a complete "
        "evidence package."
    )


def append_scope_notes(lines: list[str]) -> None:
    """Append scope notes section."""

    add_heading(lines, "Scope Notes")

    add_paragraph(
        lines,
        "The report evaluates deterministic ranking behaviour. CVSS-only and "
        "MSRC-only rankings are comparison baselines, not ground-truth remediation "
        "labels. CPRI is the Contextual Patch Remediation Index used by this "
        "project workflow."
    )

    add_paragraph(
        lines,
        "Remetria performs analysis and reporting. Vulnerability scanning, exploit "
        "testing, patch installation and production remediation execution are "
        "outside this workflow."
    )

    add_paragraph(
        lines,
        "Ranking results depend on the Kolektria scan evidence and the enrichment "
        "metadata available for the analysed CVEs. Patch age contributes to local "
        "context, but it can be constant across candidates from the same host."
    )


# ------------------------------------------------------------
# REPORT WORKFLOW
# ------------------------------------------------------------

def build_markdown_report(analysis_result: dict[str, Any]) -> str:
    """Build the Remetria Markdown report content."""

    scan_rows = get_rows(analysis_result, "ScanSummaryRows")
    cve_rows = get_rows(analysis_result, "CveRows")
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
        "CPRI methods, and exports comparison evidence for ranking evaluation."
    )

    append_analysis_outcome(
        lines=lines,
        analysis_result=analysis_result,
        scan_rows=scan_rows,
        candidate_rows=candidate_rows,
        enrichment_rows=enrichment_rows,
        ranking_rows=ranking_rows,
        evaluation_rows=evaluation_rows,
    )
    append_path_references(lines, analysis_result)
    append_runtime_input(lines, scan_rows, ranking_rows)
    append_evidence_normalisation(lines, scan_rows, cve_rows, candidate_rows)
    append_candidate_analysis(lines, scan_rows, candidate_rows)
    append_cve_enrichment(lines, enrichment_rows)
    append_ranking_method(lines)
    append_ranking_evidence(lines, scan_rows, ranking_rows)
    append_evaluation_metrics(lines, evaluation_rows)
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