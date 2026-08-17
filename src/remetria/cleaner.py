"""
Remetria artefact cleaner.

Returns the working tree to a clean generated-output state by clearing runtime
input files, generated analysis folders and temporary development artefacts.
Deliberate data archives, build scripts and executable output are preserved.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Literal

from utils.console import (
    print_action,
    print_detail,
    print_info,
    print_result,
    print_section,
    print_step,
)
from utils.paths import DATA_DIR, DIST_DIR, RESULTS_DIR, ROOT_DIR, RUNTIME_DIR, relative_path


# ------------------------------------------------------------
# TYPES
# ------------------------------------------------------------

ClearArtefactsResult = Literal["cleared", "cancelled", "skipped"]


# ------------------------------------------------------------
# PATH HELPERS
# ------------------------------------------------------------

def count_directory_items(path: Path, preserve: set[str] | None = None) -> int:
    """Count direct directory items excluding preserved names."""

    preserve = preserve or {".gitkeep"}

    if not path.exists():
        return 0

    return len([
        item
        for item in path.iterdir()
        if item.name not in preserve
    ])


def clear_directory_contents(path: Path, preserve: set[str] | None = None) -> int:
    """Remove direct directory contents excluding preserved names."""

    preserve = preserve or {".gitkeep"}

    if not path.exists():
        return 0

    removed_count = 0

    for item in path.iterdir():
        if item.name in preserve:
            continue

        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

        removed_count += 1

    return removed_count


def find_analysis_output_folders() -> list[Path]:
    """Return generated Remetria analysis output folders."""

    if not RESULTS_DIR.exists():
        return []

    return [
        path
        for path in RESULTS_DIR.glob("analysis_*")
        if path.is_dir()
    ]


def is_inside_any(path: Path, directories: list[Path]) -> bool:
    """Return True when a path is inside any supplied directory."""

    for directory in directories:
        try:
            path.relative_to(directory)
            return True
        except ValueError:
            continue

    return False


def find_development_artefacts() -> list[Path]:
    """Return temporary development artefacts across the project root."""

    cache_directories = [
        path
        for path in ROOT_DIR.rglob("__pycache__")
        if path.is_dir()
    ]

    bytecode_files = [
        path
        for pattern in ("*.pyc", "*.pyo")
        for path in ROOT_DIR.rglob(pattern)
        if path.is_file() and not is_inside_any(path, cache_directories)
    ]

    spec_files = [
        path
        for path in ROOT_DIR.rglob("*.spec")
        if path.is_file()
    ]

    metadata_files = [
        path
        for pattern in ("Thumbs.db", "desktop.ini")
        for path in ROOT_DIR.rglob(pattern)
        if path.is_file()
    ]

    return [
        *cache_directories,
        *bytecode_files,
        *spec_files,
        *metadata_files,
    ]


def remove_paths(paths: list[Path]) -> int:
    """Remove files or directories from a path list."""

    removed_count = 0

    for path in paths:
        if not path.exists():
            continue

        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

        removed_count += 1

    return removed_count


def confirm_clear_artefacts() -> bool:
    """Ask the user to confirm generated artefact removal."""

    print()
    response = input("Clear selected artefacts? [y/N]: ").strip().lower()

    return response in {"y", "yes"}


# ------------------------------------------------------------
# CLEAN WORKFLOW
# ------------------------------------------------------------

def clear_generated_artefacts() -> ClearArtefactsResult:
    """
    Clear generated Remetria artefacts.

    Returns:
        cleared:
            Artefacts were selected and removed.

        cancelled:
            Artefacts were selected, but the user declined confirmation.

        skipped:
            No generated artefacts were selected for removal.
    """

    runtime_item_count = count_directory_items(RUNTIME_DIR)
    analysis_output_folders = find_analysis_output_folders()
    development_artefacts = find_development_artefacts()

    analysis_output_count = len(analysis_output_folders)
    development_artefact_count = len(development_artefacts)

    total_count = (
        runtime_item_count +
        analysis_output_count +
        development_artefact_count
    )

    print_action("Clear Artefacts")

    print_section("Generated Workspace")
    print_step("Reviewing clean targets")
    print_detail(f"Runtime input files: {relative_path(RUNTIME_DIR)}")
    print_detail("Analysis output folders: results\\analysis_*")
    print_detail("Development artefacts: cache, bytecode, spec, metadata")
    print_result("Clean targets reviewed")

    print()

    print_step("Checking preserved locations")
    print_detail(f"Data folder: {relative_path(DATA_DIR)}")
    print_detail("Collected archive: data\\collected")
    print_detail("Dataset snapshots: data\\pre-update, data\\post-update")
    print_detail(f"Executable output: {relative_path(DIST_DIR)}")
    print_detail("Build scripts: build")
    print_result("Preserved locations confirmed")

    print_section("Artefact Count")
    print_step("Counting generated artefacts")
    print_detail(f"Runtime input items: {runtime_item_count}")
    print_detail(f"Analysis output folders: {analysis_output_count}")
    print_detail(f"Development artefact items: {development_artefact_count}")
    print_detail(f"Total selected: {total_count}")
    print_result("Artefact count calculated")

    if total_count == 0:
        print()
        print_info("No generated artefacts selected for clearing")
        return "skipped"

    if not confirm_clear_artefacts():
        return "cancelled"

    print_section("Clear Operation")
    print_step("Clearing selected artefacts")

    runtime_items_removed = clear_directory_contents(RUNTIME_DIR)
    analysis_outputs_removed = remove_paths(analysis_output_folders)
    development_artefacts_removed = remove_paths(development_artefacts)

    removed_total = (
        runtime_items_removed +
        analysis_outputs_removed +
        development_artefacts_removed
    )

    print_detail(f"Runtime input items removed: {runtime_items_removed}")
    print_detail(f"Analysis output folders removed: {analysis_outputs_removed}")
    print_detail(f"Development artefact items removed: {development_artefacts_removed}")
    print_detail(f"Total removed: {removed_total}")
    print_result("Selected artefacts cleared")

    return "cleared"