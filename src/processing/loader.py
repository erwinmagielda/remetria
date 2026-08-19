"""
Remetria scan loader.

Loads the active Remetria runtime dataset from data/runtime and validates
that each JSON file matches the expected Kolektria scan structure.
"""

from __future__ import annotations

import json
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from utils.paths import RUNTIME_DIR, relative_path


# ------------------------------------------------------------
# REQUIRED SCAN STRUCTURE
# ------------------------------------------------------------

REQUIRED_TOP_LEVEL_KEYS = [
    "Baseline",
    "InstalledKbs",
    "MonthsRequested",
    "MonthsWithEntries",
    "MsrcCoverage",
    "KbEntries",
    "SupersedenceSummary",
    "MissingKbs",
]

REQUIRED_TOP_LEVEL_TYPES = {
    "Baseline": dict,
    "InstalledKbs": list,
    "MonthsRequested": list,
    "MonthsWithEntries": list,
    "MsrcCoverage": dict,
    "KbEntries": list,
    "SupersedenceSummary": dict,
    "MissingKbs": list,
}


# ------------------------------------------------------------
# SCAN DISCOVERY
# ------------------------------------------------------------

def discover_runtime_scan_paths() -> list[Path]:
    """
    Return direct Kolektria scan files from the active runtime dataset.

    Remetria reads direct files from data/runtime. JSON files and extensionless
    scan files are accepted so exported Kolektria evidence can be staged with
    stable host labels.
    """

    if not RUNTIME_DIR.exists():
        raise RuntimeError(f"Runtime directory does not exist: {relative_path(RUNTIME_DIR)}")

    if not RUNTIME_DIR.is_dir():
        raise RuntimeError(f"Runtime path is not a directory: {relative_path(RUNTIME_DIR)}")

    scan_paths = sorted(
        path
        for path in RUNTIME_DIR.iterdir()
        if path.is_file()
        and path.name != ".gitkeep"
        and path.suffix.lower() in ["", ".json"]
    )

    if not scan_paths:
        raise RuntimeError(f"No runtime scan files found in {relative_path(RUNTIME_DIR)}")

    return scan_paths


# ------------------------------------------------------------
# JSON LOADING
# ------------------------------------------------------------

def load_scan_json(scan_path: Path) -> dict[str, Any]:
    """Load one Kolektria scan JSON file."""

    try:
        with scan_path.open("r", encoding="utf-8") as file:
            scan_data = json.load(file)

    except JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {relative_path(scan_path)}") from exc

    except OSError as exc:
        raise RuntimeError(f"Could not read {relative_path(scan_path)}") from exc

    if not isinstance(scan_data, dict):
        raise RuntimeError(f"Unexpected JSON structure in {relative_path(scan_path)}")

    return scan_data


# ------------------------------------------------------------
# STRUCTURE VALIDATION
# ------------------------------------------------------------

def validate_required_keys(scan_data: dict[str, Any], scan_path: Path) -> None:
    """Validate required Kolektria top-level keys."""

    missing_keys = [
        key
        for key in REQUIRED_TOP_LEVEL_KEYS
        if key not in scan_data
    ]

    if missing_keys:
        missing = ", ".join(missing_keys)
        raise RuntimeError(f"Missing required key(s) in {relative_path(scan_path)}: {missing}")


def validate_required_types(scan_data: dict[str, Any], scan_path: Path) -> None:
    """Validate required Kolektria top-level value types."""

    invalid_types: list[str] = []

    for key, expected_type in REQUIRED_TOP_LEVEL_TYPES.items():
        value = scan_data.get(key)

        if not isinstance(value, expected_type):
            expected_name = expected_type.__name__
            actual_name = type(value).__name__
            invalid_types.append(f"{key} expected {expected_name}, got {actual_name}")

    if invalid_types:
        invalid = "; ".join(invalid_types)
        raise RuntimeError(f"Invalid value type(s) in {relative_path(scan_path)}: {invalid}")


def validate_scan_structure(scan_data: dict[str, Any], scan_path: Path) -> None:
    """Validate one loaded Kolektria scan structure."""

    validate_required_keys(scan_data, scan_path)
    validate_required_types(scan_data, scan_path)


# ------------------------------------------------------------
# SCAN RECORDS
# ------------------------------------------------------------

def build_scan_record(
    scan_number: int,
    scan_path: Path,
    scan_data: dict[str, Any],
) -> dict[str, Any]:
    """Build a Remetria scan record from a loaded Kolektria scan."""

    return {
        "ScanId": str(scan_number),
        "ScanPath": scan_path,
        "ScanData": scan_data,
    }


def load_runtime_scans() -> list[dict[str, Any]]:
    """Load and validate all active runtime scans."""

    loaded_scans: list[dict[str, Any]] = []

    for scan_number, scan_path in enumerate(discover_runtime_scan_paths(), start=1):
        scan_data = load_scan_json(scan_path)
        validate_scan_structure(scan_data, scan_path)

        loaded_scans.append(
            build_scan_record(
                scan_number=scan_number,
                scan_path=scan_path,
                scan_data=scan_data,
            )
        )

    return loaded_scans