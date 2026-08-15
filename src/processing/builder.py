"""
Remetria candidate builder.

Builds missing KB remediation candidate rows from loaded Kolektria scan records.
These rows form the base dataset for ranking, evaluation, and reporting.
"""

from __future__ import annotations

from typing import Any

from processing.normaliser import join_values, safe_list
from utils.paths import relative_path


# ------------------------------------------------------------
# LOOKUP HELPERS
# ------------------------------------------------------------

def build_kb_entry_lookup(kb_entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a lookup of KB entry records by KB identifier."""

    lookup: dict[str, dict[str, Any]] = {}

    for kb_entry in kb_entries:
        kb_id = str(kb_entry.get("KB", "")).strip()

        if kb_id:
            lookup[kb_id] = kb_entry

    return lookup


def count_unique_values(values: list[Any]) -> int:
    """Count unique string values in a list."""

    return len({
        str(value)
        for value in values
    })


def build_missing_kb_prevalence(candidate_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build missing KB prevalence details across the runtime dataset."""

    prevalence: dict[str, dict[str, Any]] = {}

    for candidate_row in candidate_rows:
        kb_id = candidate_row["KB"]
        scan_id = candidate_row["ScanId"]

        if kb_id not in prevalence:
            prevalence[kb_id] = {
                "ScanIds": [],
                "ScanCount": 0,
            }

        if scan_id not in prevalence[kb_id]["ScanIds"]:
            prevalence[kb_id]["ScanIds"].append(scan_id)

    for kb_id, details in prevalence.items():
        details["ScanIds"] = sorted(details["ScanIds"])
        details["ScanCount"] = len(details["ScanIds"])

    return prevalence


def apply_missing_kb_prevalence(candidate_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add runtime missing KB prevalence fields to candidate rows."""

    prevalence = build_missing_kb_prevalence(candidate_rows)

    for candidate_row in candidate_rows:
        kb_id = candidate_row["KB"]
        details = prevalence[kb_id]

        candidate_row["MissingInRuntimeScanCount"] = details["ScanCount"]
        candidate_row["MissingInRuntimeScanIds"] = join_values(details["ScanIds"])

    return candidate_rows


# ------------------------------------------------------------
# CANDIDATE ROWS
# ------------------------------------------------------------

def build_candidate_row(
    scan_record: dict[str, Any],
    kb_id: str,
    candidate_index: int,
) -> dict[str, Any]:
    """Build one missing KB remediation candidate row."""

    scan_id = scan_record["ScanId"]
    scan_path = scan_record["ScanPath"]
    scan_data = scan_record["ScanData"]

    baseline = scan_data["Baseline"]
    installed_kbs = set(str(kb) for kb in safe_list(scan_data["InstalledKbs"]))
    missing_kbs = set(str(kb) for kb in safe_list(scan_data["MissingKbs"]))
    kb_entries = safe_list(scan_data["KbEntries"])
    msrc_coverage = scan_data["MsrcCoverage"]
    supersedence_summary = scan_data["SupersedenceSummary"]

    expected_kbs = set(
        str(kb)
        for kb in safe_list(supersedence_summary.get("ExpectedKbs"))
    )

    installed_or_superseded_kbs = set(
        str(kb)
        for kb in safe_list(supersedence_summary.get("InstalledOrSupersededKbs"))
    )

    kb_entry_lookup = build_kb_entry_lookup(kb_entries)
    kb_entry = kb_entry_lookup.get(kb_id, {})
    expected_kbs = set(kb_entry_lookup.keys())

    is_expected = kb_id in expected_kbs
    is_installed = kb_id in installed_kbs
    is_missing = kb_id in missing_kbs
    is_installed_or_superseded = is_expected and not is_missing

    cves = safe_list(kb_entry.get("Cves"))
    months = safe_list(kb_entry.get("Months"))
    supersedes = safe_list(kb_entry.get("Supersedes"))

    return {
        "ScanId": scan_id,
        "SourcePath": relative_path(scan_path),
        "CandidateIndex": candidate_index,
        "KB": kb_id,
        "OsName": baseline.get("OsName", ""),
        "OsEdition": baseline.get("OsEdition", ""),
        "DisplayVersion": baseline.get("DisplayVersion", ""),
        "Build": baseline.get("Build", ""),
        "Architecture": baseline.get("Architecture", ""),
        "ProductNameHint": baseline.get("ProductNameHint", ""),
        "LcuMonthId": baseline.get("LcuMonthId", ""),
        "LcuPackageName": baseline.get("LcuPackageName", ""),
        "PatchAgeDays": baseline.get("PatchAgeDays", ""),
        "CoverageStatus": msrc_coverage.get("CoverageStatus", ""),
        "KbEntryFound": bool(kb_entry),
        "Months": join_values(months),
        "MonthCount": count_unique_values(months),
        "CveCount": len(cves),
        "UniqueCveCount": count_unique_values(cves),
        "Supersedes": join_values(supersedes),
        "SupersedesCount": count_unique_values(supersedes),
        "UpdateType": kb_entry.get("UpdateType", ""),
        "IsExpected": is_expected,
        "IsInstalled": is_installed,
        "IsInstalledOrSuperseded": is_installed_or_superseded,
        "IsMissing": is_missing,
        "RelationshipsResolved": supersedence_summary.get("RelationshipsResolved", 0),
    }


def build_candidate_rows_for_scan(scan_record: dict[str, Any]) -> list[dict[str, Any]]:
    """Build missing KB candidate rows for one scan record."""

    scan_data = scan_record["ScanData"]
    missing_kbs = sorted(str(kb) for kb in safe_list(scan_data["MissingKbs"]))

    candidate_rows: list[dict[str, Any]] = []

    for candidate_index, kb_id in enumerate(missing_kbs, start=1):
        candidate_rows.append(
            build_candidate_row(
                scan_record=scan_record,
                kb_id=kb_id,
                candidate_index=candidate_index,
            )
        )

    return candidate_rows


def build_kb_candidate_rows(loaded_scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build missing KB candidate rows from loaded runtime scans."""

    candidate_rows: list[dict[str, Any]] = []

    for scan_record in loaded_scans:
        candidate_rows.extend(
            build_candidate_rows_for_scan(scan_record)
        )

    return apply_missing_kb_prevalence(candidate_rows)