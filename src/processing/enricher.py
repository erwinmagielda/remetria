"""
Remetria CVE metadata enricher.

Fetches Microsoft CVRF advisory documents for the MonthIds already present in
Kolektria evidence, extracts CVE-level severity and CVSS metadata, and joins
that metadata back into missing KB remediation candidates.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from processing.normaliser import join_values, safe_list


# ------------------------------------------------------------
# CONSTANTS
# ------------------------------------------------------------

MSRC_API_BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0"
MSRC_API_VERSION = "api-version=2023-11-01"
REQUEST_TIMEOUT_SECONDS = 60

SEVERITY_ORDER = {
    "Critical": 4,
    "Important": 3,
    "High": 3,
    "Moderate": 2,
    "Medium": 2,
    "Low": 1,
    "None": 0,
    "Unknown": 0,
    "": 0,
}

CVSS_SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "NONE": 0,
    "UNKNOWN": 0,
    "": 0,
}

CVSS_VECTOR_VALUE_MAP = {
    "AV": {
        "N": "NETWORK",
        "A": "ADJACENT_NETWORK",
        "L": "LOCAL",
        "P": "PHYSICAL",
    },
    "AC": {
        "L": "LOW",
        "H": "HIGH",
    },
    "PR": {
        "N": "NONE",
        "L": "LOW",
        "H": "HIGH",
    },
    "UI": {
        "N": "NONE",
        "R": "REQUIRED",
    },
    "S": {
        "U": "UNCHANGED",
        "C": "CHANGED",
    },
    "C": {
        "H": "HIGH",
        "L": "LOW",
        "N": "NONE",
    },
    "I": {
        "H": "HIGH",
        "L": "LOW",
        "N": "NONE",
    },
    "A": {
        "H": "HIGH",
        "L": "LOW",
        "N": "NONE",
    },
}


# ------------------------------------------------------------
# BASIC VALUE HELPERS
# ------------------------------------------------------------

def normalise_text(value: Any) -> str:
    """Return a stripped string value."""

    if value is None:
        return ""

    return str(value).strip()


def normalise_cve_id(value: Any) -> str:
    """Return a normalised CVE identifier."""

    return normalise_text(value).upper()


def split_joined_values(value: Any) -> list[str]:
    """Split semicolon-separated table values into a list."""

    if isinstance(value, list):
        return [
            normalise_text(item)
            for item in value
            if normalise_text(item)
        ]

    text = normalise_text(value)

    if not text:
        return []

    return [
        item.strip()
        for item in text.split(";")
        if item.strip()
    ]


def unique_sorted(values: list[Any]) -> list[str]:
    """Return unique string values in sorted order."""

    return sorted({
        normalise_text(value)
        for value in values
        if normalise_text(value)
    })


def parse_float(value: Any) -> float:
    """Return a float value or 0.0 when conversion fails."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def calculate_cvss_severity(base_score: float) -> str:
    """Return a CVSS severity label from a base score."""

    if base_score >= 9.0:
        return "CRITICAL"

    if base_score >= 7.0:
        return "HIGH"

    if base_score >= 4.0:
        return "MEDIUM"

    if base_score > 0.0:
        return "LOW"

    return "UNKNOWN"


def pick_highest_severity(severities: list[str]) -> str:
    """Return the highest MSRC severity from a list."""

    if not severities:
        return ""

    return max(
        severities,
        key=lambda severity: SEVERITY_ORDER.get(severity, 0),
    )


def pick_highest_cvss_severity(severities: list[str]) -> str:
    """Return the highest CVSS severity from a list."""

    if not severities:
        return ""

    return max(
        severities,
        key=lambda severity: CVSS_SEVERITY_ORDER.get(severity.upper(), 0),
    )


# ------------------------------------------------------------
# CVSS VECTOR PARSING
# ------------------------------------------------------------

def parse_cvss_vector(vector: str) -> dict[str, str]:
    """Parse selected CVSS vector fields."""

    parsed = {
        "AttackVector": "",
        "AttackComplexity": "",
        "PrivilegesRequired": "",
        "UserInteraction": "",
        "Scope": "",
        "ConfidentialityImpact": "",
        "IntegrityImpact": "",
        "AvailabilityImpact": "",
    }

    vector = normalise_text(vector)

    if not vector:
        return parsed

    parts = [
        part
        for part in vector.split("/")
        if ":" in part
    ]

    vector_values: dict[str, str] = {}

    for part in parts:
        key, value = part.split(":", 1)
        vector_values[key] = value

    parsed["AttackVector"] = CVSS_VECTOR_VALUE_MAP["AV"].get(
        vector_values.get("AV", ""),
        "",
    )
    parsed["AttackComplexity"] = CVSS_VECTOR_VALUE_MAP["AC"].get(
        vector_values.get("AC", ""),
        "",
    )
    parsed["PrivilegesRequired"] = CVSS_VECTOR_VALUE_MAP["PR"].get(
        vector_values.get("PR", ""),
        "",
    )
    parsed["UserInteraction"] = CVSS_VECTOR_VALUE_MAP["UI"].get(
        vector_values.get("UI", ""),
        "",
    )
    parsed["Scope"] = CVSS_VECTOR_VALUE_MAP["S"].get(
        vector_values.get("S", ""),
        "",
    )
    parsed["ConfidentialityImpact"] = CVSS_VECTOR_VALUE_MAP["C"].get(
        vector_values.get("C", ""),
        "",
    )
    parsed["IntegrityImpact"] = CVSS_VECTOR_VALUE_MAP["I"].get(
        vector_values.get("I", ""),
        "",
    )
    parsed["AvailabilityImpact"] = CVSS_VECTOR_VALUE_MAP["A"].get(
        vector_values.get("A", ""),
        "",
    )

    return parsed


# ------------------------------------------------------------
# HTTP
# ------------------------------------------------------------

def get_msrc_cvrf_url(month_id: str) -> str:
    """Return the MSRC CVRF URL for one MonthId."""

    return f"{MSRC_API_BASE_URL}/cvrf/{month_id}?{MSRC_API_VERSION}"


def fetch_json(url: str) -> dict[str, Any]:
    """Fetch JSON from a URL using stdlib only."""

    request = Request(
        url=url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Remetria/0.1",
        },
    )

    try:
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            response_body = response.read().decode("utf-8")

    except HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} while fetching {url}") from exc

    except URLError as exc:
        raise RuntimeError(f"Network error while fetching {url}") from exc

    try:
        data = json.loads(response_body)

    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON returned from {url}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected JSON shape returned from {url}")

    return data


def load_msrc_cvrf_document(month_id: str) -> dict[str, Any]:
    """Load one MSRC CVRF document from the MSRC API."""

    url = get_msrc_cvrf_url(month_id)

    return fetch_json(url)


# ------------------------------------------------------------
# CVRF FIELD EXTRACTION
# ------------------------------------------------------------

def get_description_value(value: Any) -> str:
    """Return a CVRF description value from common shapes."""

    if isinstance(value, dict):
        return normalise_text(value.get("Value"))

    return normalise_text(value)


def get_note_value(note: dict[str, Any]) -> str:
    """Return a CVRF note text value."""

    return get_description_value(note.get("Value"))


def get_vulnerability_title(vulnerability: dict[str, Any]) -> str:
    """Return CVRF vulnerability title text."""

    title = vulnerability.get("Title")

    return get_description_value(title)


def get_vulnerability_description(vulnerability: dict[str, Any]) -> str:
    """Return CVRF vulnerability description text."""

    notes = safe_list(vulnerability.get("Notes"))

    for note in notes:
        if not isinstance(note, dict):
            continue

        note_type = normalise_text(note.get("Type")).lower()

        if note_type == "description":
            return get_note_value(note)

    return ""


def extract_threat_values(
    vulnerability: dict[str, Any],
    accepted_types: set[str],
) -> list[str]:
    """Extract threat descriptions by CVRF threat Type values."""

    values: list[str] = []

    for threat in safe_list(vulnerability.get("Threats")):
        if not isinstance(threat, dict):
            continue

        threat_type = normalise_text(threat.get("Type")).lower()

        if threat_type not in accepted_types:
            continue

        description = get_description_value(threat.get("Description"))

        if description:
            values.append(description)

    return unique_sorted(values)


def extract_msrc_severity(vulnerability: dict[str, Any]) -> str:
    """Extract the highest MSRC severity value from CVRF threats."""

    values = extract_threat_values(
        vulnerability=vulnerability,
        accepted_types={"3", "severity"},
    )

    recognised = [
        value
        for value in values
        if value in SEVERITY_ORDER
    ]

    if recognised:
        return pick_highest_severity(recognised)

    return join_values(values)


def extract_msrc_impact(vulnerability: dict[str, Any]) -> str:
    """Extract MSRC impact values from CVRF threats."""

    values = extract_threat_values(
        vulnerability=vulnerability,
        accepted_types={"0", "impact"},
    )

    return join_values(values)


def extract_msrc_exploit_status(vulnerability: dict[str, Any]) -> str:
    """Extract MSRC exploit-related values from CVRF threats."""

    values = extract_threat_values(
        vulnerability=vulnerability,
        accepted_types={"1", "exploit status", "exploitability"},
    )

    return join_values(values)


def is_publicly_disclosed(text: str) -> bool:
    """Return whether MSRC text states public disclosure."""

    normalised = text.lower().replace(" ", "")

    return "publiclydisclosed:yes" in normalised


def is_known_exploited(text: str) -> bool:
    """Return whether MSRC text states known exploitation."""

    normalised = text.lower().replace(" ", "")

    return (
        "exploited:yes" in normalised or
        "exploitationdetected" in normalised or
        "exploitedinthewild" in normalised
    )

def extract_cvss_score_sets(vulnerability: dict[str, Any]) -> list[dict[str, Any]]:
    """Return CVSS score set dictionaries from CVRF."""

    score_sets = vulnerability.get("CVSSScoreSets")

    if isinstance(score_sets, list):
        return [
            score_set
            for score_set in score_sets
            if isinstance(score_set, dict)
        ]

    return []


def select_cvss_score_set(score_sets: list[dict[str, Any]]) -> dict[str, Any]:
    """Select the highest available CVSS base score set."""

    if not score_sets:
        return {}

    return max(
        score_sets,
        key=lambda score_set: parse_float(score_set.get("BaseScore")),
    )


def build_msrc_vulnerability_row(
    vulnerability: dict[str, Any],
    month_id: str,
) -> dict[str, Any]:
    """Build one CVE enrichment row from a CVRF vulnerability entry."""

    cve_id = normalise_cve_id(vulnerability.get("CVE"))
    score_sets = extract_cvss_score_sets(vulnerability)
    selected_score_set = select_cvss_score_set(score_sets)

    cvss_base_score = parse_float(selected_score_set.get("BaseScore"))
    cvss_temporal_score = parse_float(selected_score_set.get("TemporalScore"))
    cvss_vector = normalise_text(selected_score_set.get("Vector"))
    cvss_metrics = parse_cvss_vector(cvss_vector)

    msrc_severity = extract_msrc_severity(vulnerability)
    msrc_impact = extract_msrc_impact(vulnerability)
    msrc_exploit_status = extract_msrc_exploit_status(vulnerability)

    exploit_text = " ".join([
        msrc_exploit_status,
        join_values(extract_threat_values(vulnerability, {"1"})),
    ])

    return {
        "CVE": cve_id,
        "EnrichmentStatus": "resolved",
        "EnrichmentSource": "MSRC_CVRF",
        "MsrcMonths": month_id,
        "MsrcTitle": get_vulnerability_title(vulnerability),
        "MsrcDescription": get_vulnerability_description(vulnerability),
        "MsrcMaximumSeverity": msrc_severity,
        "MsrcSeverityRank": SEVERITY_ORDER.get(msrc_severity, 0),
        "MsrcImpact": msrc_impact,
        "MsrcExploitStatus": msrc_exploit_status,
        "MsrcPubliclyDisclosed": is_publicly_disclosed(exploit_text),
        "MsrcKnownExploited": is_known_exploited(exploit_text),
        "CvssScoreSetCount": len(score_sets),
        "CvssBaseScore": cvss_base_score,
        "CvssTemporalScore": cvss_temporal_score,
        "CvssSeverity": calculate_cvss_severity(cvss_base_score),
        "CvssVector": cvss_vector,
        "AttackVector": cvss_metrics["AttackVector"],
        "AttackComplexity": cvss_metrics["AttackComplexity"],
        "PrivilegesRequired": cvss_metrics["PrivilegesRequired"],
        "UserInteraction": cvss_metrics["UserInteraction"],
        "Scope": cvss_metrics["Scope"],
        "ConfidentialityImpact": cvss_metrics["ConfidentialityImpact"],
        "IntegrityImpact": cvss_metrics["IntegrityImpact"],
        "AvailabilityImpact": cvss_metrics["AvailabilityImpact"],
    }


def merge_duplicate_cve_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Merge duplicate CVE rows across multiple MSRC months."""

    merged: dict[str, dict[str, Any]] = {}

    for row in rows:
        cve_id = row["CVE"]

        if cve_id not in merged:
            merged[cve_id] = row
            continue

        current = merged[cve_id]

        current_months = split_joined_values(current.get("MsrcMonths"))
        row_months = split_joined_values(row.get("MsrcMonths"))
        current["MsrcMonths"] = join_values(unique_sorted(current_months + row_months))

        if parse_float(row.get("CvssBaseScore")) > parse_float(current.get("CvssBaseScore")):
            for key in [
                "CvssBaseScore",
                "CvssTemporalScore",
                "CvssSeverity",
                "CvssVector",
                "AttackVector",
                "AttackComplexity",
                "PrivilegesRequired",
                "UserInteraction",
                "Scope",
                "ConfidentialityImpact",
                "IntegrityImpact",
                "AvailabilityImpact",
            ]:
                current[key] = row.get(key, "")

        current["CvssScoreSetCount"] = max(
            int(current.get("CvssScoreSetCount", 0)),
            int(row.get("CvssScoreSetCount", 0)),
        )

        current["MsrcMaximumSeverity"] = pick_highest_severity([
            normalise_text(current.get("MsrcMaximumSeverity")),
            normalise_text(row.get("MsrcMaximumSeverity")),
        ])
        current["MsrcSeverityRank"] = SEVERITY_ORDER.get(
            current["MsrcMaximumSeverity"],
            0,
        )

        current["MsrcImpact"] = join_values(
            unique_sorted(
                split_joined_values(current.get("MsrcImpact")) +
                split_joined_values(row.get("MsrcImpact"))
            )
        )
        current["MsrcExploitStatus"] = join_values(
            unique_sorted(
                split_joined_values(current.get("MsrcExploitStatus")) +
                split_joined_values(row.get("MsrcExploitStatus"))
            )
        )
        current["MsrcPubliclyDisclosed"] = (
            bool(current.get("MsrcPubliclyDisclosed")) or
            bool(row.get("MsrcPubliclyDisclosed"))
        )
        current["MsrcKnownExploited"] = (
            bool(current.get("MsrcKnownExploited")) or
            bool(row.get("MsrcKnownExploited"))
        )

    return merged


def build_msrc_cve_index(month_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Build a CVE metadata index from required MSRC MonthIds."""

    vulnerability_rows: list[dict[str, Any]] = []

    for month_id in month_ids:
        cvrf_document = load_msrc_cvrf_document(month_id)
        vulnerabilities = safe_list(cvrf_document.get("Vulnerability"))

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            cve_id = normalise_cve_id(vulnerability.get("CVE"))

            if not cve_id:
                continue

            vulnerability_rows.append(
                build_msrc_vulnerability_row(
                    vulnerability=vulnerability,
                    month_id=month_id,
                )
            )

    return merge_duplicate_cve_rows(vulnerability_rows)


# ------------------------------------------------------------
# CVE ROW PREPARATION
# ------------------------------------------------------------

def extract_required_month_ids(cve_rows: list[dict[str, Any]]) -> list[str]:
    """Extract unique MSRC MonthIds from CVE rows."""

    month_ids: list[str] = []

    for cve_row in cve_rows:
        for month_id in split_joined_values(cve_row.get("Months")):
            if month_id not in month_ids:
                month_ids.append(month_id)

    return sorted(month_ids)


def extract_required_cve_ids(cve_rows: list[dict[str, Any]]) -> list[str]:
    """Extract unique CVE IDs from CVE rows."""

    cve_ids = [
        normalise_cve_id(cve_row.get("CVE"))
        for cve_row in cve_rows
    ]

    return unique_sorted(cve_ids)


def build_missing_enrichment_row(cve_id: str) -> dict[str, Any]:
    """Build a placeholder row when enrichment is unavailable."""

    return {
        "CVE": cve_id,
        "EnrichmentStatus": "missing_msrc_metadata",
        "EnrichmentSource": "",
        "MsrcMonths": "",
        "MsrcTitle": "",
        "MsrcDescription": "",
        "MsrcMaximumSeverity": "",
        "MsrcSeverityRank": 0,
        "MsrcImpact": "",
        "MsrcExploitStatus": "",
        "MsrcPubliclyDisclosed": False,
        "MsrcKnownExploited": False,
        "CvssScoreSetCount": 0,
        "CvssBaseScore": 0.0,
        "CvssTemporalScore": 0.0,
        "CvssSeverity": "UNKNOWN",
        "CvssVector": "",
        "AttackVector": "",
        "AttackComplexity": "",
        "PrivilegesRequired": "",
        "UserInteraction": "",
        "Scope": "",
        "ConfidentialityImpact": "",
        "IntegrityImpact": "",
        "AvailabilityImpact": "",
    }


def build_cve_enrichment_rows(cve_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build unique CVE enrichment rows for all observed CVEs."""

    required_month_ids = extract_required_month_ids(cve_rows)
    required_cve_ids = extract_required_cve_ids(cve_rows)

    msrc_cve_index = build_msrc_cve_index(required_month_ids)

    enrichment_rows: list[dict[str, Any]] = []

    for cve_id in required_cve_ids:
        enrichment_rows.append(
            msrc_cve_index.get(
                cve_id,
                build_missing_enrichment_row(cve_id),
            )
        )

    return enrichment_rows


# ------------------------------------------------------------
# CANDIDATE ENRICHMENT
# ------------------------------------------------------------

def build_candidate_cve_lookup(cve_rows: list[dict[str, Any]]) -> dict[tuple[str, str], list[str]]:
    """Build a lookup from ScanId/KB to CVE IDs."""

    lookup: dict[tuple[str, str], list[str]] = {}

    for cve_row in cve_rows:
        scan_id = normalise_text(cve_row.get("ScanId"))
        kb_id = normalise_text(cve_row.get("KB"))
        cve_id = normalise_cve_id(cve_row.get("CVE"))

        if not scan_id or not kb_id or not cve_id:
            continue

        key = (scan_id, kb_id)

        if key not in lookup:
            lookup[key] = []

        if cve_id not in lookup[key]:
            lookup[key].append(cve_id)

    for key, cve_ids in lookup.items():
        lookup[key] = sorted(cve_ids)

    return lookup


def count_enriched_values(rows: list[dict[str, Any]], field: str, value: Any) -> int:
    """Count enrichment rows where field equals value."""

    return len([
        row
        for row in rows
        if row.get(field) == value
    ])


def count_truthy_values(rows: list[dict[str, Any]], field: str) -> int:
    """Count enrichment rows where field is truthy."""

    return len([
        row
        for row in rows
        if bool(row.get(field))
    ])


def count_high_impact_rows(rows: list[dict[str, Any]]) -> int:
    """Count rows with high confidentiality, integrity, or availability impact."""

    return len([
        row
        for row in rows
        if "HIGH" in {
            normalise_text(row.get("ConfidentialityImpact")),
            normalise_text(row.get("IntegrityImpact")),
            normalise_text(row.get("AvailabilityImpact")),
        }
    ])


def average_cvss_score(rows: list[dict[str, Any]]) -> float:
    """Return average CVSS base score across rows with a score."""

    scores = [
        parse_float(row.get("CvssBaseScore"))
        for row in rows
        if parse_float(row.get("CvssBaseScore")) > 0
    ]

    if not scores:
        return 0.0

    return round(sum(scores) / len(scores), 2)


def max_cvss_score(rows: list[dict[str, Any]]) -> float:
    """Return maximum CVSS base score."""

    scores = [
        parse_float(row.get("CvssBaseScore"))
        for row in rows
    ]

    if not scores:
        return 0.0

    return max(scores)


def highest_msrc_severity(rows: list[dict[str, Any]]) -> str:
    """Return highest MSRC severity across enrichment rows."""

    severities = [
        normalise_text(row.get("MsrcMaximumSeverity"))
        for row in rows
        if normalise_text(row.get("MsrcMaximumSeverity"))
    ]

    return pick_highest_severity(severities)


def highest_cvss_severity(rows: list[dict[str, Any]]) -> str:
    """Return highest CVSS severity across enrichment rows."""

    severities = [
        normalise_text(row.get("CvssSeverity"))
        for row in rows
        if normalise_text(row.get("CvssSeverity"))
    ]

    return pick_highest_cvss_severity(severities)


def build_enriched_candidate_row(
    candidate_row: dict[str, Any],
    candidate_cve_lookup: dict[tuple[str, str], list[str]],
    enrichment_lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build one enriched missing KB candidate row."""

    scan_id = normalise_text(candidate_row.get("ScanId"))
    kb_id = normalise_text(candidate_row.get("KB"))
    cve_ids = candidate_cve_lookup.get((scan_id, kb_id), [])

    enrichment_rows = [
        enrichment_lookup.get(
            cve_id,
            build_missing_enrichment_row(cve_id),
        )
        for cve_id in cve_ids
    ]

    max_msrc_severity = highest_msrc_severity(enrichment_rows)

    enriched_row = dict(candidate_row)

    enriched_row.update({
        "CandidateCves": join_values(cve_ids),
        "EnrichedCveCount": count_enriched_values(
            enrichment_rows,
            "EnrichmentStatus",
            "resolved",
        ),
        "MissingEnrichmentCount": count_enriched_values(
            enrichment_rows,
            "EnrichmentStatus",
            "missing_msrc_metadata",
        ),
        "MaxCvssBaseScore": max_cvss_score(enrichment_rows),
        "AverageCvssBaseScore": average_cvss_score(enrichment_rows),
        "MaxCvssSeverity": highest_cvss_severity(enrichment_rows),
        "MaxMsrcSeverity": max_msrc_severity,
        "MaxMsrcSeverityRank": SEVERITY_ORDER.get(
            max_msrc_severity,
            0,
        ),
        "CriticalCveCount": count_enriched_values(
            enrichment_rows,
            "CvssSeverity",
            "CRITICAL",
        ),
        "HighCveCount": count_enriched_values(
            enrichment_rows,
            "CvssSeverity",
            "HIGH",
        ),
        "MediumCveCount": count_enriched_values(
            enrichment_rows,
            "CvssSeverity",
            "MEDIUM",
        ),
        "LowCveCount": count_enriched_values(
            enrichment_rows,
            "CvssSeverity",
            "LOW",
        ),
        "NetworkAttackVectorCount": count_enriched_values(
            enrichment_rows,
            "AttackVector",
            "NETWORK",
        ),
        "NoPrivilegesRequiredCount": count_enriched_values(
            enrichment_rows,
            "PrivilegesRequired",
            "NONE",
        ),
        "NoUserInteractionCount": count_enriched_values(
            enrichment_rows,
            "UserInteraction",
            "NONE",
        ),
        "HighImpactCveCount": count_high_impact_rows(enrichment_rows),
        "MsrcKnownExploitedCount": count_truthy_values(
            enrichment_rows,
            "MsrcKnownExploited",
        ),
        "MsrcPubliclyDisclosedCount": count_truthy_values(
            enrichment_rows,
            "MsrcPubliclyDisclosed",
        ),
        "MsrcImpactValues": join_values(
            unique_sorted([
                row.get("MsrcImpact")
                for row in enrichment_rows
                if row.get("MsrcImpact")
            ])
        ),
    })

    return enriched_row


def build_enriched_kb_candidate_rows(
    kb_candidate_rows: list[dict[str, Any]],
    cve_rows: list[dict[str, Any]],
    cve_enrichment_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Join CVE enrichment metadata into missing KB candidate rows."""

    candidate_cve_lookup = build_candidate_cve_lookup(cve_rows)

    enrichment_lookup = {
        row["CVE"]: row
        for row in cve_enrichment_rows
    }

    return [
        build_enriched_candidate_row(
            candidate_row=candidate_row,
            candidate_cve_lookup=candidate_cve_lookup,
            enrichment_lookup=enrichment_lookup,
        )
        for candidate_row in kb_candidate_rows
    ]


# ------------------------------------------------------------
# ENRICHMENT WORKFLOW
# ------------------------------------------------------------

def enrich_analysis_rows(
    cve_rows: list[dict[str, Any]],
    kb_candidate_rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Build Remetria enrichment row groups."""

    cve_enrichment_rows = build_cve_enrichment_rows(cve_rows)

    enriched_kb_candidate_rows = build_enriched_kb_candidate_rows(
        kb_candidate_rows=kb_candidate_rows,
        cve_rows=cve_rows,
        cve_enrichment_rows=cve_enrichment_rows,
    )

    return {
        "CveEnrichmentRows": cve_enrichment_rows,
        "EnrichedKbCandidateRows": enriched_kb_candidate_rows,
    }