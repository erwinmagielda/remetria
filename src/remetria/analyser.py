"""
Remetria analysis workflow.

Provides the main menu and active runtime dataset intake flow.
"""

from __future__ import annotations

from typing import Any

from processing.loader import load_runtime_scans
from remetria.cleaner import clear_generated_artefacts
from utils.console import (
    print_action,
    print_banner,
    print_detail,
    print_error,
    print_info,
    print_menu_title,
    print_result,
    print_section,
    print_step,
    print_success,
    prompt_main_menu,
)
from utils.paths import ensure_output_directories, ensure_required_directories, relative_path


# ------------------------------------------------------------
# SCAN DISPLAY
# ------------------------------------------------------------

def print_loaded_scan_details(loaded_scans: list[dict[str, Any]]) -> None:
    """Print accepted runtime scan records."""

    for scan_record in loaded_scans:
        scan_id = scan_record["ScanId"]
        scan_path = scan_record["ScanPath"]

        print_detail(f"Scan ID: {scan_id}")
        print_detail(f"Source: {relative_path(scan_path)}")


# ------------------------------------------------------------
# ANALYSIS WORKFLOW
# ------------------------------------------------------------

def run_analysis() -> None:
    """Run the Remetria analysis workflow."""

    print_action("Run Analysis")

    print_section("Environment Preparation")

    print_step("Validating required directories")
    ensure_required_directories()
    print_result("Required directories found")

    print_step("Preparing output directories")
    ensure_output_directories()
    print_result("Output directories prepared")

    print_section("Runtime Dataset")

    print_step("Loading active runtime scans")
    loaded_scans = load_runtime_scans()
    print_result("Runtime scans loaded")
    print_detail(f"Scans loaded: {len(loaded_scans)}")

    print_loaded_scan_details(loaded_scans)

    print_section("Analysis Status")

    print_info("Normalisation is not implemented yet")
    print_info("Next step: build processing/normaliser.py")

    print_success("Run Analysis completed")


# ------------------------------------------------------------
# ARTEFACT CLEANUP
# ------------------------------------------------------------

def clear_artefacts() -> None:
    """Run the clear artefacts workflow."""

    result = clear_generated_artefacts()

    if result == "cleared":
        print_success("Clear Artefacts completed")
        return

    if result == "cancelled":
        print_info("Clear Artefacts cancelled")
        return

    print_info("Clear Artefacts skipped")


# ------------------------------------------------------------
# MAIN MENU
# ------------------------------------------------------------

def main() -> None:
    """Run the Remetria main menu."""

    print_banner()

    while True:
        selection = prompt_main_menu()

        if selection == "1":
            try:
                run_analysis()
            except RuntimeError as exc:
                print_error(str(exc))

            print_menu_title()

        elif selection == "2":
            try:
                clear_artefacts()
            except RuntimeError as exc:
                print_error(str(exc))

            print_menu_title()

        elif selection == "3":
            print_info("Exit")
            break

        else:
            print_error("Invalid option")
            print_menu_title()


if __name__ == "__main__":
    main()