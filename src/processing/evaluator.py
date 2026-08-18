"""
Remetria ranking evaluator.

Summarises the ranking comparison produced by ranker.py into per-scan and
aggregate evaluation metrics for ranking analysis.
"""

from __future__ import annotations

from typing import Any


# ------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------

TOP_N = 3


# ------------------------------------------------------------
# VALUE HELPERS
# ------------------------------------------------------------

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


def round_metric(value: float) -> float:
    """Round a metric value for stable exported output."""

    return round(value, 6)


def average(values: list[float]) -> float:
    """Return the average of a numeric list."""

    if not values:
        return 0.0

    return round_metric(sum(values) / len(values))


def ratio(numerator: int, denominator: int) -> float:
    """Return a safe ratio."""

    if denominator <= 0:
        return 0.0

    return round_metric(numerator / denominator)


def get_kb(row: dict[str, Any] | None) -> str:
    """Return a KB identifier from a row."""

    if row is None:
        return ""

    return str(row.get("KB", ""))


# ------------------------------------------------------------
# GROUPING
# ------------------------------------------------------------

def group_rows_by_scan_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group ranking rows by ScanId."""

    grouped_rows: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        scan_id = str(row.get("ScanId", ""))

        if scan_id not in grouped_rows:
            grouped_rows[scan_id] = []

        grouped_rows[scan_id].append(row)

    return grouped_rows


# ------------------------------------------------------------
# RANK HELPERS
# ------------------------------------------------------------

def sort_by_rank(rows: list[dict[str, Any]], rank_field: str) -> list[dict[str, Any]]:
    """Sort rows by a ranking field."""

    return sorted(
        rows,
        key=lambda row: (
            as_int(row.get(rank_field)),
            str(row.get("KB", "")),
        ),
    )


def get_top_row(rows: list[dict[str, Any]], rank_field: str) -> dict[str, Any] | None:
    """Return the top-ranked row for a ranking field."""

    sorted_rows = sort_by_rank(rows, rank_field)

    if not sorted_rows:
        return None

    return sorted_rows[0]


def get_top_kbs(
    rows: list[dict[str, Any]],
    rank_field: str,
    top_n: int,
) -> list[str]:
    """Return top-N KB identifiers for a ranking field."""

    sorted_rows = sort_by_rank(rows, rank_field)

    return [
        str(row.get("KB", ""))
        for row in sorted_rows[:top_n]
    ]


def top_n_overlap(
    rows: list[dict[str, Any]],
    baseline_rank_field: str,
    cpri_rank_field: str,
    top_n: int,
) -> int:
    """Return top-N overlap count between a baseline and CPRI."""

    effective_top_n = min(top_n, len(rows))

    baseline_top = set(
        get_top_kbs(
            rows=rows,
            rank_field=baseline_rank_field,
            top_n=effective_top_n,
        )
    )
    cpri_top = set(
        get_top_kbs(
            rows=rows,
            rank_field=cpri_rank_field,
            top_n=effective_top_n,
        )
    )

    return len(baseline_top.intersection(cpri_top))


# ------------------------------------------------------------
# MOVEMENT HELPERS
# ------------------------------------------------------------

def get_signed_movements(rows: list[dict[str, Any]], delta_field: str) -> list[int]:
    """Return signed rank movement values from a delta field."""

    return [
        as_int(row.get(delta_field))
        for row in rows
    ]


def get_absolute_movements(rows: list[dict[str, Any]], delta_field: str) -> list[int]:
    """Return absolute rank movement values from a delta field."""

    return [
        abs(as_int(row.get(delta_field)))
        for row in rows
    ]


def get_largest_positive_movement_row(
    rows: list[dict[str, Any]],
    delta_field: str,
) -> dict[str, Any] | None:
    """Return the row with the largest positive CPRI movement."""

    positive_rows = [
        row
        for row in rows
        if as_int(row.get(delta_field)) > 0
    ]

    if not positive_rows:
        return None

    return max(
        positive_rows,
        key=lambda row: (
            as_int(row.get(delta_field)),
            str(row.get("KB", "")),
        ),
    )


def get_largest_negative_movement_row(
    rows: list[dict[str, Any]],
    delta_field: str,
) -> dict[str, Any] | None:
    """Return the row with the largest negative CPRI movement."""

    negative_rows = [
        row
        for row in rows
        if as_int(row.get(delta_field)) < 0
    ]

    if not negative_rows:
        return None

    return min(
        negative_rows,
        key=lambda row: (
            as_int(row.get(delta_field)),
            str(row.get("KB", "")),
        ),
    )


# ------------------------------------------------------------
# SCORE HELPERS
# ------------------------------------------------------------

def get_score_values(rows: list[dict[str, Any]], score_field: str) -> list[float]:
    """Return numeric score values from rows."""

    return [
        as_float(row.get(score_field))
        for row in rows
    ]


def get_min_score(rows: list[dict[str, Any]], score_field: str) -> float:
    """Return the minimum score value for a field."""

    values = get_score_values(rows, score_field)

    if not values:
        return 0.0

    return round_metric(min(values))


def get_max_score(rows: list[dict[str, Any]], score_field: str) -> float:
    """Return the maximum score value for a field."""

    values = get_score_values(rows, score_field)

    if not values:
        return 0.0

    return round_metric(max(values))


# ------------------------------------------------------------
# SCAN-LEVEL METRICS
# ------------------------------------------------------------

def build_scan_evaluation_row(
    scan_id: str,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one per-scan evaluation metrics row."""

    candidate_count = len(rows)
    effective_top_n = min(TOP_N, candidate_count)

    cvss_top_1 = get_top_row(rows, "CVSSRank")
    msrc_top_1 = get_top_row(rows, "MSRCRank")
    cpri_top_1 = get_top_row(rows, "CPRIRank")

    cvss_top_1_kb = get_kb(cvss_top_1)
    msrc_top_1_kb = get_kb(msrc_top_1)
    cpri_top_1_kb = get_kb(cpri_top_1)

    cvss_cpri_top_n_overlap = top_n_overlap(
        rows=rows,
        baseline_rank_field="CVSSRank",
        cpri_rank_field="CPRIRank",
        top_n=TOP_N,
    )
    msrc_cpri_top_n_overlap = top_n_overlap(
        rows=rows,
        baseline_rank_field="MSRCRank",
        cpri_rank_field="CPRIRank",
        top_n=TOP_N,
    )

    cpri_vs_cvss_signed = get_signed_movements(
        rows=rows,
        delta_field="CPRIvsCVSSRankDelta",
    )
    cpri_vs_msrc_signed = get_signed_movements(
        rows=rows,
        delta_field="CPRIvsMSRCRankDelta",
    )
    cpri_vs_cvss_absolute = get_absolute_movements(
        rows=rows,
        delta_field="CPRIvsCVSSRankDelta",
    )
    cpri_vs_msrc_absolute = get_absolute_movements(
        rows=rows,
        delta_field="CPRIvsMSRCRankDelta",
    )

    cvss_up_row = get_largest_positive_movement_row(
        rows=rows,
        delta_field="CPRIvsCVSSRankDelta",
    )
    cvss_down_row = get_largest_negative_movement_row(
        rows=rows,
        delta_field="CPRIvsCVSSRankDelta",
    )
    msrc_up_row = get_largest_positive_movement_row(
        rows=rows,
        delta_field="CPRIvsMSRCRankDelta",
    )
    msrc_down_row = get_largest_negative_movement_row(
        rows=rows,
        delta_field="CPRIvsMSRCRankDelta",
    )

    return {
        "EvaluationScope": "scan",
        "ScanId": scan_id,
        "CandidateCount": candidate_count,
        "EffectiveTopN": effective_top_n,
        "CVSSTop1KB": cvss_top_1_kb,
        "MSRCTop1KB": msrc_top_1_kb,
        "CPRITop1KB": cpri_top_1_kb,
        "CPRIMatchesCVSSTop1": cpri_top_1_kb == cvss_top_1_kb,
        "CPRIMatchesMSRCTop1": cpri_top_1_kb == msrc_top_1_kb,
        "CVSSCPRITopNOverlapCount": cvss_cpri_top_n_overlap,
        "CVSSCPRITopNOverlapRatio": ratio(
            cvss_cpri_top_n_overlap,
            effective_top_n,
        ),
        "MSRCCPRITopNOverlapCount": msrc_cpri_top_n_overlap,
        "MSRCCPRITopNOverlapRatio": ratio(
            msrc_cpri_top_n_overlap,
            effective_top_n,
        ),
        "AverageSignedCPRIvsCVSSMovement": average([
            float(value)
            for value in cpri_vs_cvss_signed
        ]),
        "AverageSignedCPRIvsMSRCMovement": average([
            float(value)
            for value in cpri_vs_msrc_signed
        ]),
        "AverageAbsoluteCPRIvsCVSSMovement": average([
            float(value)
            for value in cpri_vs_cvss_absolute
        ]),
        "AverageAbsoluteCPRIvsMSRCMovement": average([
            float(value)
            for value in cpri_vs_msrc_absolute
        ]),
        "MaxAbsoluteCPRIvsCVSSMovement": max(cpri_vs_cvss_absolute, default=0),
        "MaxAbsoluteCPRIvsMSRCMovement": max(cpri_vs_msrc_absolute, default=0),
        "LargestCPRIvsCVSSUpKB": get_kb(cvss_up_row),
        "LargestCPRIvsCVSSUpDelta": as_int(
            cvss_up_row.get("CPRIvsCVSSRankDelta")
            if cvss_up_row else 0
        ),
        "LargestCPRIvsCVSSDownKB": get_kb(cvss_down_row),
        "LargestCPRIvsCVSSDownDelta": as_int(
            cvss_down_row.get("CPRIvsCVSSRankDelta")
            if cvss_down_row else 0
        ),
        "LargestCPRIvsMSRCUpKB": get_kb(msrc_up_row),
        "LargestCPRIvsMSRCUpDelta": as_int(
            msrc_up_row.get("CPRIvsMSRCRankDelta")
            if msrc_up_row else 0
        ),
        "LargestCPRIvsMSRCDownKB": get_kb(msrc_down_row),
        "LargestCPRIvsMSRCDownDelta": as_int(
            msrc_down_row.get("CPRIvsMSRCRankDelta")
            if msrc_down_row else 0
        ),
        "MinimumCPRIScore": get_min_score(rows, "CPRIScore"),
        "MaximumCPRIScore": get_max_score(rows, "CPRIScore"),
        "AverageCPRIScore": average(get_score_values(rows, "CPRIScore")),
    }


def build_scan_evaluation_rows(
    ranking_comparison_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build per-scan evaluation rows."""

    grouped_rows = group_rows_by_scan_id(ranking_comparison_rows)

    return [
        build_scan_evaluation_row(
            scan_id=scan_id,
            rows=grouped_rows[scan_id],
        )
        for scan_id in sorted(grouped_rows)
    ]


# ------------------------------------------------------------
# AGGREGATE METRICS
# ------------------------------------------------------------

def count_true(rows: list[dict[str, Any]], field: str) -> int:
    """Count rows where a boolean-like field is true."""

    return len([
        row
        for row in rows
        if bool(row.get(field))
    ])


def average_metric(rows: list[dict[str, Any]], field: str) -> float:
    """Return the average value for a metric field."""

    return average([
        as_float(row.get(field))
        for row in rows
    ])


def sum_metric(rows: list[dict[str, Any]], field: str) -> int:
    """Return the integer sum for a metric field."""

    return sum(
        as_int(row.get(field))
        for row in rows
    )


def build_aggregate_evaluation_row(
    scan_evaluation_rows: list[dict[str, Any]],
    ranking_comparison_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one aggregate evaluation metrics row."""

    candidate_bearing_scan_count = len(scan_evaluation_rows)
    total_candidate_count = len(ranking_comparison_rows)

    cvss_top_1_match_count = count_true(
        scan_evaluation_rows,
        "CPRIMatchesCVSSTop1",
    )
    msrc_top_1_match_count = count_true(
        scan_evaluation_rows,
        "CPRIMatchesMSRCTop1",
    )

    cpri_vs_cvss_absolute = get_absolute_movements(
        rows=ranking_comparison_rows,
        delta_field="CPRIvsCVSSRankDelta",
    )
    cpri_vs_msrc_absolute = get_absolute_movements(
        rows=ranking_comparison_rows,
        delta_field="CPRIvsMSRCRankDelta",
    )

    return {
        "EvaluationScope": "aggregate",
        "ScanId": "ALL",
        "CandidateCount": total_candidate_count,
        "CandidateBearingScanCount": candidate_bearing_scan_count,
        "EffectiveTopN": TOP_N,
        "CVSSTop1KB": "",
        "MSRCTop1KB": "",
        "CPRITop1KB": "",
        "CPRIMatchesCVSSTop1": "",
        "CPRIMatchesMSRCTop1": "",
        "CVSSTop1MatchCount": cvss_top_1_match_count,
        "CVSSTop1MatchRatio": ratio(
            cvss_top_1_match_count,
            candidate_bearing_scan_count,
        ),
        "MSRCTop1MatchCount": msrc_top_1_match_count,
        "MSRCTop1MatchRatio": ratio(
            msrc_top_1_match_count,
            candidate_bearing_scan_count,
        ),
        "CVSSCPRITopNOverlapCount": sum_metric(
            scan_evaluation_rows,
            "CVSSCPRITopNOverlapCount",
        ),
        "CVSSCPRITopNOverlapRatio": average_metric(
            scan_evaluation_rows,
            "CVSSCPRITopNOverlapRatio",
        ),
        "MSRCCPRITopNOverlapCount": sum_metric(
            scan_evaluation_rows,
            "MSRCCPRITopNOverlapCount",
        ),
        "MSRCCPRITopNOverlapRatio": average_metric(
            scan_evaluation_rows,
            "MSRCCPRITopNOverlapRatio",
        ),
        "AverageSignedCPRIvsCVSSMovement": average([
            float(value)
            for value in get_signed_movements(
                rows=ranking_comparison_rows,
                delta_field="CPRIvsCVSSRankDelta",
            )
        ]),
        "AverageSignedCPRIvsMSRCMovement": average([
            float(value)
            for value in get_signed_movements(
                rows=ranking_comparison_rows,
                delta_field="CPRIvsMSRCRankDelta",
            )
        ]),
        "AverageAbsoluteCPRIvsCVSSMovement": average([
            float(value)
            for value in cpri_vs_cvss_absolute
        ]),
        "AverageAbsoluteCPRIvsMSRCMovement": average([
            float(value)
            for value in cpri_vs_msrc_absolute
        ]),
        "MaxAbsoluteCPRIvsCVSSMovement": max(cpri_vs_cvss_absolute, default=0),
        "MaxAbsoluteCPRIvsMSRCMovement": max(cpri_vs_msrc_absolute, default=0),
        "LargestCPRIvsCVSSUpKB": "",
        "LargestCPRIvsCVSSUpDelta": "",
        "LargestCPRIvsCVSSDownKB": "",
        "LargestCPRIvsCVSSDownDelta": "",
        "LargestCPRIvsMSRCUpKB": "",
        "LargestCPRIvsMSRCUpDelta": "",
        "LargestCPRIvsMSRCDownKB": "",
        "LargestCPRIvsMSRCDownDelta": "",
        "MinimumCPRIScore": get_min_score(
            ranking_comparison_rows,
            "CPRIScore",
        ),
        "MaximumCPRIScore": get_max_score(
            ranking_comparison_rows,
            "CPRIScore",
        ),
        "AverageCPRIScore": average(
            get_score_values(
                ranking_comparison_rows,
                "CPRIScore",
            )
        ),
    }


# ------------------------------------------------------------
# EVALUATION WORKFLOW
# ------------------------------------------------------------

def evaluate_ranking_comparison(
    ranking_comparison_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build Remetria evaluation metric rows."""

    scan_evaluation_rows = build_scan_evaluation_rows(ranking_comparison_rows)

    aggregate_evaluation_row = build_aggregate_evaluation_row(
        scan_evaluation_rows=scan_evaluation_rows,
        ranking_comparison_rows=ranking_comparison_rows,
    )

    return [
        *scan_evaluation_rows,
        aggregate_evaluation_row,
    ]