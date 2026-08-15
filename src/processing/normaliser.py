"""
Remetria evidence normaliser.

Converts loaded Kolektria scan records into structured scan summary and CVE
rows for downstream candidate building, ranking, evaluation, and export.
"""

from __future__ import annotations

from typing import Any

from utils.paths import relative_path


# ------------------------------------------------------------
# VALUE HELPERS
# ------------------------------------------------------------

def safe_list(value: Any) -> list[Any]:
    """Return a list value or an empty list when the value is not a list."""

    if isinstance(value, list):
        return value

    return []


def join_values(values: list[Any]) -> str:
    """Join list values into a stable semicolon-separated string."""

    return "; ".join(str(value) for value in values)


def count_value(value: Any) -> int:
    """Return a count from an integer or list value."""

    if isinstance(value, int):
        return value

    if isinstance(value, list):
        return len(value)

    return 0


def count_unique_cves(kb_entries: list[dict[str, Any]]) -> int:
    """Count unique CVE identifiers across KB entries."""

    unique_cves: set[str] = set()

    for kb_entry in kb_entries:
        for cve_id in safe_list(kb_entry.get("Cves")):
            unique_cves.add(str(cve_id))

    return len(unique_cves)


def count_total_cve_links(kb_entries: list[dict[str, Any]]) -> int:
    """Count total KB-to-CVE links across KB entries."""

    total_links = 0

    for kb_entry in kb_entries:
        total_links += len(safe_list(kb_entry.get("Cves")))

    return total_links


# ------------------------------------------------------------
# SCAN SUMMARY ROWS
# ------------------------------------------------------------

def build_scan_summary_row(scan_record: dict[str, Any]) -> dict[str, Any]:
    """Build one scan summary row from a loaded scan record."""

    scan_id = scan_record["ScanId"]
    scan_path = scan_record["ScanPath"]
    scan_data = scan_record["ScanData"]

    baseline = scan_data["Baseline"]
    installed_kbs = safe_list(scan_data["InstalledKbs"])
    months_requested = safe_list(scan_data["MonthsRequested"])
    months_with_entries = safe_list(scan_data["MonthsWithEntries"])
    msrc_coverage = scan_data["MsrcCoverage"]
    kb_entries = safe_list(scan_data["KbEntries"])
    supersedence_summary = scan_data["SupersedenceSummary"]
    missing_kbs = safe_list(scan_data["MissingKbs"])

    expected_kb_count = count_value(supersedence_summary.get("ExpectedKbs"))
    installed_or_superseded_kb_count = count_value(
        supersedence_summary.get("InstalledOrSupersededKbs")
    )

    return {
        "ScanId": scan_id,
        "SourcePath": relative_path(scan_path),
        "OsName": baseline.get("OsName", ""),
        "OsEdition": baseline.get("OsEdition", ""),
        "DisplayVersion": baseline.get("DisplayVersion", ""),
        "Build": baseline.get("Build", ""),
        "Architecture": baseline.get("Architecture", ""),
        "LcuMonthId": baseline.get("LcuMonthId", ""),
        "LcuPackageName": baseline.get("LcuPackageName", ""),
        "LcuInstallMonth": baseline.get("LcuInstallMonth", ""),
        "PatchAgeDays": baseline.get("PatchAgeDays", ""),
        "CoverageStatus": msrc_coverage.get("CoverageStatus", ""),
        "MonthsRequested": join_values(months_requested),
        "MonthsWithEntries": join_values(months_with_entries),
        "InstalledKbCount": len(installed_kbs),
        "ExpectedKbCount": expected_kb_count,
        "InstalledOrSupersededKbCount": installed_or_superseded_kb_count,
        "KbEntryCount": len(kb_entries),
        "MissingKbCount": len(missing_kbs),
        "RelationshipsResolved": supersedence_summary.get("RelationshipsResolved", 0),
        "TotalCveLinks": count_total_cve_links(kb_entries),
        "UniqueCveCount": count_unique_cves(kb_entries),
    }


def build_scan_summary_rows(loaded_scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build scan summary rows from loaded scan records."""

    return [
        build_scan_summary_row(scan_record)
        for scan_record in loaded_scans
    ]


# ------------------------------------------------------------
# CVE ROWS
# ------------------------------------------------------------

def build_cve_rows_for_kb_entry(
    scan_record: dict[str, Any],
    kb_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build CVE evidence rows for one KB entry."""

    scan_id = scan_record["ScanId"]
    scan_path = scan_record["ScanPath"]
    scan_data = scan_record["ScanData"]

    installed_kbs = set(str(kb) for kb in safe_list(scan_data["InstalledKbs"]))
    missing_kbs = set(str(kb) for kb in safe_list(scan_data["MissingKbs"]))

    kb_id = str(kb_entry.get("KB", ""))
    months = safe_list(kb_entry.get("Months"))
    cves = safe_list(kb_entry.get("Cves"))
    supersedes = safe_list(kb_entry.get("Supersedes"))
    update_type = kb_entry.get("UpdateType", "")

    cve_rows: list[dict[str, Any]] = []

    for index, cve_id in enumerate(cves, start=1):
        cve_rows.append({
            "ScanId": scan_id,
            "SourcePath": relative_path(scan_path),
            "KB": kb_id,
            "CVE": str(cve_id),
            "CveOrdinal": index,
            "Months": join_values(months),
            "UpdateType": update_type,
            "Supersedes": join_values(supersedes),
            "IsInstalled": kb_id in installed_kbs,
            "IsMissing": kb_id in missing_kbs,
        })

    return cve_rows


def build_cve_rows(loaded_scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build CVE evidence rows from loaded scan records."""

    cve_rows: list[dict[str, Any]] = []

    for scan_record in loaded_scans:
        scan_data = scan_record["ScanData"]
        kb_entries = safe_list(scan_data["KbEntries"])

        for kb_entry in kb_entries:
            cve_rows.extend(
                build_cve_rows_for_kb_entry(
                    scan_record=scan_record,
                    kb_entry=kb_entry,
                )
            )

    return cve_rows


# ------------------------------------------------------------
# NORMALISATION WORKFLOW
# ------------------------------------------------------------

def normalise_loaded_scans(loaded_scans: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Normalise loaded scan records into structured row groups."""

    return {
        "ScanSummaryRows": build_scan_summary_rows(loaded_scans),
        "CveRows": build_cve_rows(loaded_scans),
    }