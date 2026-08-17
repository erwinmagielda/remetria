"""
Remetria candidate ranker.

Builds deterministic ranking comparisons for missing KB remediation candidates.

The module produces three ranking methods:

CVSS:
    Vulnerability-score baseline using CVSS-derived candidate fields.

MSRC:
    Microsoft advisory baseline using MSRC severity and advisory signals.

CPRI:
    Contextual Patch Remediation Index, the Remetria context-aware method.
"""

from __future__ import annotations

from typing import Any


# ------------------------------------------------------------
# RANKING METHOD NAMES
# ------------------------------------------------------------

CVSS_METHOD = "CVSS"
MSRC_METHOD = "MSRC"
CPRI_METHOD = "CPRI"

RANK_SCOPE = "per-scan"


# ------------------------------------------------------------
# CPRI WEIGHTS
# ------------------------------------------------------------

CPRI_SEVERITY_WEIGHT = 0.35
CPRI_EXPLOITABILITY_WEIGHT = 0.25
CPRI_LOCAL_CONTEXT_WEIGHT = 0.25
CPRI_IMPACT_BREADTH_WEIGHT = 0.15

CPRI_SEVERITY_CVSS_WEIGHT = 0.60
CPRI_SEVERITY_MSRC_WEIGHT = 0.40

CPRI_EXPLOITABILITY_NETWORK_WEIGHT = 0.25
CPRI_EXPLOITABILITY_NO_PRIVILEGES_WEIGHT = 0.20
CPRI_EXPLOITABILITY_NO_USER_INTERACTION_WEIGHT = 0.20
CPRI_EXPLOITABILITY_KNOWN_EXPLOITED_WEIGHT = 0.25
CPRI_EXPLOITABILITY_PUBLIC_DISCLOSURE_WEIGHT = 0.10

CPRI_LOCAL_PATCH_AGE_WEIGHT = 0.40
CPRI_LOCAL_PREVALENCE_WEIGHT = 0.25
CPRI_LOCAL_CVE_VOLUME_WEIGHT = 0.25
CPRI_LOCAL_SUPERSEDENCE_WEIGHT = 0.10

CPRI_IMPACT_HIGH_IMPACT_WEIGHT = 0.70
CPRI_IMPACT_CRITICAL_CVE_WEIGHT = 0.30


# ------------------------------------------------------------
# BASIC VALUE HELPERS
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


def round_score(value: float) -> float:
    """Round a score for stable exported output."""

    return round(value, 6)


def safe_divide(numerator: Any, denominator: Any) -> float:
    """Return numerator divided by denominator, or zero when denominator is zero."""

    denominator_value = as_float(denominator)

    if denominator_value <= 0:
        return 0.0

    return as_float(numerator) / denominator_value


def binary_flag(value: Any) -> int:
    """Return 1 when a numeric value is greater than zero, otherwise 0."""

    return 1 if as_float(value) > 0 else 0


def clamp_score(value: float) -> float:
    """Clamp a score into the 0.0 to 1.0 range."""

    if value < 0.0:
        return 0.0

    if value > 1.0:
        return 1.0

    return value


# ------------------------------------------------------------
# NORMALISATION
# ------------------------------------------------------------

def max_numeric_value(rows: list[dict[str, Any]], key: str) -> float:
    """Return the maximum numeric value for a field across rows."""

    values = [
        as_float(row.get(key))
        for row in rows
    ]

    if not values:
        return 0.0

    return max(values)


def normalise(value: Any, maximum: float) -> float:
    """Normalise a numeric value against the runtime maximum."""

    if maximum <= 0:
        return 0.0

    return clamp_score(as_float(value) / maximum)


def build_normalisation_context(
    enriched_kb_candidate_rows: list[dict[str, Any]],
) -> dict[str, float]:
    """Build runtime-wide normalisation values for ranking."""

    return {
        "MaxCvssBaseScore": max_numeric_value(
            enriched_kb_candidate_rows,
            "MaxCvssBaseScore",
        ),
        "CriticalCveCount": max_numeric_value(
            enriched_kb_candidate_rows,
            "CriticalCveCount",
        ),
        "HighCveCount": max_numeric_value(
            enriched_kb_candidate_rows,
            "HighCveCount",
        ),
        "PatchAgeDays": max_numeric_value(
            enriched_kb_candidate_rows,
            "PatchAgeDays",
        ),
        "MissingInRuntimeScanCount": max_numeric_value(
            enriched_kb_candidate_rows,
            "MissingInRuntimeScanCount",
        ),
        "UniqueCveCount": max_numeric_value(
            enriched_kb_candidate_rows,
            "UniqueCveCount",
        ),
        "SupersedesCount": max_numeric_value(
            enriched_kb_candidate_rows,
            "SupersedesCount",
        ),
    }


# ------------------------------------------------------------
# BASELINE SCORES
# ------------------------------------------------------------

def calculate_cvss_score(
    candidate_row: dict[str, Any],
    normalisation_context: dict[str, float],
) -> float:
    """
    Calculate the CVSS-only baseline score.

    The score uses only CVSS-derived fields already aggregated into the KB
    candidate row.
    """

    max_cvss_score = normalise(
        candidate_row.get("MaxCvssBaseScore"),
        normalisation_context["MaxCvssBaseScore"],
    )
    critical_cve_score = normalise(
        candidate_row.get("CriticalCveCount"),
        normalisation_context["CriticalCveCount"],
    )
    high_cve_score = normalise(
        candidate_row.get("HighCveCount"),
        normalisation_context["HighCveCount"],
    )

    score = (
        (max_cvss_score * 0.70) +
        (critical_cve_score * 0.20) +
        (high_cve_score * 0.10)
    )

    return round_score(score)


def calculate_msrc_score(candidate_row: dict[str, Any]) -> float:
    """
    Calculate the MSRC-only baseline score.

    The score uses Microsoft advisory-derived fields already aggregated into
    the KB candidate row.
    """

    severity_score = safe_divide(
        candidate_row.get("MaxMsrcSeverityRank"),
        4,
    )
    known_exploited_score = binary_flag(
        candidate_row.get("MsrcKnownExploitedCount")
    )
    public_disclosure_score = binary_flag(
        candidate_row.get("MsrcPubliclyDisclosedCount")
    )

    score = (
        (severity_score * 0.70) +
        (known_exploited_score * 0.20) +
        (public_disclosure_score * 0.10)
    )

    return round_score(score)


# ------------------------------------------------------------
# CPRI COMPONENT SCORES
# ------------------------------------------------------------

def calculate_cpri_severity_score(
    candidate_row: dict[str, Any],
    normalisation_context: dict[str, float],
) -> float:
    """Calculate the CPRI severity component."""

    cvss_score = normalise(
        candidate_row.get("MaxCvssBaseScore"),
        normalisation_context["MaxCvssBaseScore"],
    )
    msrc_score = safe_divide(
        candidate_row.get("MaxMsrcSeverityRank"),
        4,
    )

    score = (
        (cvss_score * CPRI_SEVERITY_CVSS_WEIGHT) +
        (msrc_score * CPRI_SEVERITY_MSRC_WEIGHT)
    )

    return round_score(score)


def calculate_cpri_exploitability_score(candidate_row: dict[str, Any]) -> float:
    """Calculate the CPRI exploitability component."""

    unique_cve_count = candidate_row.get("UniqueCveCount")

    network_attack_score = safe_divide(
        candidate_row.get("NetworkAttackVectorCount"),
        unique_cve_count,
    )
    no_privileges_score = safe_divide(
        candidate_row.get("NoPrivilegesRequiredCount"),
        unique_cve_count,
    )
    no_user_interaction_score = safe_divide(
        candidate_row.get("NoUserInteractionCount"),
        unique_cve_count,
    )
    known_exploited_score = binary_flag(
        candidate_row.get("MsrcKnownExploitedCount")
    )
    public_disclosure_score = binary_flag(
        candidate_row.get("MsrcPubliclyDisclosedCount")
    )

    score = (
        (network_attack_score * CPRI_EXPLOITABILITY_NETWORK_WEIGHT) +
        (no_privileges_score * CPRI_EXPLOITABILITY_NO_PRIVILEGES_WEIGHT) +
        (no_user_interaction_score * CPRI_EXPLOITABILITY_NO_USER_INTERACTION_WEIGHT) +
        (known_exploited_score * CPRI_EXPLOITABILITY_KNOWN_EXPLOITED_WEIGHT) +
        (public_disclosure_score * CPRI_EXPLOITABILITY_PUBLIC_DISCLOSURE_WEIGHT)
    )

    return round_score(score)


def calculate_cpri_local_context_score(
    candidate_row: dict[str, Any],
    normalisation_context: dict[str, float],
) -> float:
    """Calculate the CPRI local patch context component."""

    patch_age_score = normalise(
        candidate_row.get("PatchAgeDays"),
        normalisation_context["PatchAgeDays"],
    )
    prevalence_score = normalise(
        candidate_row.get("MissingInRuntimeScanCount"),
        normalisation_context["MissingInRuntimeScanCount"],
    )
    cve_volume_score = normalise(
        candidate_row.get("UniqueCveCount"),
        normalisation_context["UniqueCveCount"],
    )
    supersedence_score = normalise(
        candidate_row.get("SupersedesCount"),
        normalisation_context["SupersedesCount"],
    )

    score = (
        (patch_age_score * CPRI_LOCAL_PATCH_AGE_WEIGHT) +
        (prevalence_score * CPRI_LOCAL_PREVALENCE_WEIGHT) +
        (cve_volume_score * CPRI_LOCAL_CVE_VOLUME_WEIGHT) +
        (supersedence_score * CPRI_LOCAL_SUPERSEDENCE_WEIGHT)
    )

    return round_score(score)


def calculate_cpri_impact_breadth_score(
    candidate_row: dict[str, Any],
    normalisation_context: dict[str, float],
) -> float:
    """Calculate the CPRI impact breadth component."""

    unique_cve_count = candidate_row.get("UniqueCveCount")

    high_impact_score = safe_divide(
        candidate_row.get("HighImpactCveCount"),
        unique_cve_count,
    )
    critical_cve_score = normalise(
        candidate_row.get("CriticalCveCount"),
        normalisation_context["CriticalCveCount"],
    )

    score = (
        (high_impact_score * CPRI_IMPACT_HIGH_IMPACT_WEIGHT) +
        (critical_cve_score * CPRI_IMPACT_CRITICAL_CVE_WEIGHT)
    )

    return round_score(score)


def calculate_cpri_score(
    severity_score: float,
    exploitability_score: float,
    local_context_score: float,
    impact_breadth_score: float,
) -> float:
    """Calculate the final CPRI score."""

    score = (
        (severity_score * CPRI_SEVERITY_WEIGHT) +
        (exploitability_score * CPRI_EXPLOITABILITY_WEIGHT) +
        (local_context_score * CPRI_LOCAL_CONTEXT_WEIGHT) +
        (impact_breadth_score * CPRI_IMPACT_BREADTH_WEIGHT)
    )

    return round_score(score)


# ------------------------------------------------------------
# RANKING ROWS
# ------------------------------------------------------------

def build_scored_candidate_row(
    candidate_row: dict[str, Any],
    normalisation_context: dict[str, float],
) -> dict[str, Any]:
    """Build one candidate row with CVSS, MSRC, and CPRI scores."""

    cvss_score = calculate_cvss_score(
        candidate_row=candidate_row,
        normalisation_context=normalisation_context,
    )
    msrc_score = calculate_msrc_score(candidate_row)

    cpri_severity_score = calculate_cpri_severity_score(
        candidate_row=candidate_row,
        normalisation_context=normalisation_context,
    )
    cpri_exploitability_score = calculate_cpri_exploitability_score(candidate_row)
    cpri_local_context_score = calculate_cpri_local_context_score(
        candidate_row=candidate_row,
        normalisation_context=normalisation_context,
    )
    cpri_impact_breadth_score = calculate_cpri_impact_breadth_score(
        candidate_row=candidate_row,
        normalisation_context=normalisation_context,
    )

    cpri_score = calculate_cpri_score(
        severity_score=cpri_severity_score,
        exploitability_score=cpri_exploitability_score,
        local_context_score=cpri_local_context_score,
        impact_breadth_score=cpri_impact_breadth_score,
    )

    ranking_row = dict(candidate_row)

    ranking_row.update({
        "RankingScope": RANK_SCOPE,
        "CVSSScore": cvss_score,
        "MSRCScore": msrc_score,
        "CPRISeverityScore": cpri_severity_score,
        "CPRIExploitabilityScore": cpri_exploitability_score,
        "CPRILocalContextScore": cpri_local_context_score,
        "CPRIImpactBreadthScore": cpri_impact_breadth_score,
        "CPRIScore": cpri_score,
        "CPRISeverityWeight": CPRI_SEVERITY_WEIGHT,
        "CPRIExploitabilityWeight": CPRI_EXPLOITABILITY_WEIGHT,
        "CPRILocalContextWeight": CPRI_LOCAL_CONTEXT_WEIGHT,
        "CPRIImpactBreadthWeight": CPRI_IMPACT_BREADTH_WEIGHT,
    })

    return ranking_row


def build_scored_candidate_rows(
    enriched_kb_candidate_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build scored candidate rows from enriched KB candidate rows."""

    normalisation_context = build_normalisation_context(enriched_kb_candidate_rows)

    return [
        build_scored_candidate_row(
            candidate_row=candidate_row,
            normalisation_context=normalisation_context,
        )
        for candidate_row in enriched_kb_candidate_rows
    ]


# ------------------------------------------------------------
# RANK ASSIGNMENT
# ------------------------------------------------------------

def group_rows_by_scan_id(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group rows by ScanId."""

    grouped_rows: dict[str, list[dict[str, Any]]] = {}

    for row in rows:
        scan_id = str(row.get("ScanId", ""))

        if scan_id not in grouped_rows:
            grouped_rows[scan_id] = []

        grouped_rows[scan_id].append(row)

    return grouped_rows


def sort_for_cvss_rank(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort rows for CVSS-only ranking."""

    return sorted(
        rows,
        key=lambda row: (
            -as_float(row.get("CVSSScore")),
            -as_float(row.get("MaxCvssBaseScore")),
            -as_float(row.get("CriticalCveCount")),
            -as_float(row.get("HighCveCount")),
            str(row.get("KB", "")),
        ),
    )


def sort_for_msrc_rank(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort rows for MSRC-only ranking."""

    return sorted(
        rows,
        key=lambda row: (
            -as_float(row.get("MSRCScore")),
            -as_float(row.get("MaxMsrcSeverityRank")),
            -as_float(row.get("MsrcKnownExploitedCount")),
            -as_float(row.get("MsrcPubliclyDisclosedCount")),
            str(row.get("KB", "")),
        ),
    )


def sort_for_cpri_rank(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort rows for CPRI context-aware ranking."""

    return sorted(
        rows,
        key=lambda row: (
            -as_float(row.get("CPRIScore")),
            -as_float(row.get("CPRILocalContextScore")),
            -as_float(row.get("CPRIExploitabilityScore")),
            -as_float(row.get("CPRISeverityScore")),
            str(row.get("KB", "")),
        ),
    )


def assign_rank(
    rows: list[dict[str, Any]],
    rank_field: str,
    sorted_rows: list[dict[str, Any]],
) -> None:
    """Assign ranking positions to rows in-place."""

    row_lookup = {
        (row.get("ScanId"), row.get("KB")): row
        for row in rows
    }

    for rank, row in enumerate(sorted_rows, start=1):
        key = (row.get("ScanId"), row.get("KB"))
        row_lookup[key][rank_field] = rank


def assign_ranks_for_scan(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign CVSS, MSRC, and CPRI ranks to one scan group."""

    ranked_rows = [
        dict(row)
        for row in rows
    ]

    assign_rank(
        rows=ranked_rows,
        rank_field="CVSSRank",
        sorted_rows=sort_for_cvss_rank(ranked_rows),
    )
    assign_rank(
        rows=ranked_rows,
        rank_field="MSRCRank",
        sorted_rows=sort_for_msrc_rank(ranked_rows),
    )
    assign_rank(
        rows=ranked_rows,
        rank_field="CPRIRank",
        sorted_rows=sort_for_cpri_rank(ranked_rows),
    )

    return sort_for_cpri_rank(ranked_rows)


def add_rank_movement_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Add rank movement fields comparing CPRI to the two baselines."""

    ranked_row = dict(row)

    cvss_rank = as_int(ranked_row.get("CVSSRank"))
    msrc_rank = as_int(ranked_row.get("MSRCRank"))
    cpri_rank = as_int(ranked_row.get("CPRIRank"))

    ranked_row["CPRIvsCVSSRankDelta"] = cvss_rank - cpri_rank
    ranked_row["CPRIvsMSRCRankDelta"] = msrc_rank - cpri_rank

    return ranked_row


def assign_all_ranks(scored_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign ranks within each scan group."""

    grouped_rows = group_rows_by_scan_id(scored_rows)
    ranking_rows: list[dict[str, Any]] = []

    for scan_id in sorted(grouped_rows):
        scan_rows = assign_ranks_for_scan(grouped_rows[scan_id])

        ranking_rows.extend(
            add_rank_movement_fields(row)
            for row in scan_rows
        )

    return ranking_rows


# ------------------------------------------------------------
# RANKING WORKFLOW
# ------------------------------------------------------------

def rank_enriched_kb_candidates(
    enriched_kb_candidate_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build ranking comparison rows from enriched KB candidate rows."""

    scored_rows = build_scored_candidate_rows(enriched_kb_candidate_rows)

    return assign_all_ranks(scored_rows)