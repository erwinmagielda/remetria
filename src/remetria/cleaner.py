"""
Remetria artefact cleaner.

Removes generated analysis folders, build workspace files and Python cache
artefacts. Active runtime scans and executable output are intentionally
preserved.
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
    print_step,
)
from utils.paths import (
    BUILD_PYINSTALLER_DIR,
    DIST_DIR,
    RESULTS_DIR,
    ROOT_DIR,
    RUNTIME_DIR,
    relative_path,
)


# ------------------------------------------------------------
# TYPES
# ------------------------------------------------------------

ClearArtefactsResult = Literal["cleared", "cancelled", "skipped"]


# ------------------------------------------------------------
# CLEAN HELPERS
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


def find_analysis_run_directories() -> list[Path]:
    """Return generated Remetria analysis output folders."""

    if not RESULTS_DIR.exists():
        return []

    return [
        path
        for path in RESULTS_DIR.glob("analysis_*")
        if path.is_dir()
    ]


def find_python_cache_directories() -> list[Path]:
    """Return Python cache directories under the project root."""

    return [
        path
        for path in ROOT_DIR.rglob("__pycache__")
        if path.is_dir()
    ]


def find_python_bytecode_files() -> list[Path]:
    """Return Python bytecode files under the project root."""

    return [
        *ROOT_DIR.rglob("*.pyc"),
        *ROOT_DIR.rglob("*.pyo"),
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
    response = input("Clear generated artefacts? [y/N]: ").strip().lower()

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

    analysis_run_directories = find_analysis_run_directories()
    cache_directories = find_python_cache_directories()
    bytecode_files = find_python_bytecode_files()

    analysis_run_count = len(analysis_run_directories)
    pyinstaller_count = count_directory_items(BUILD_PYINSTALLER_DIR)
    bytecode_count = len(bytecode_files)
    cache_count = len(cache_directories)

    total_count = (
        analysis_run_count +
        pyinstaller_count +
        bytecode_count +
        cache_count
    )

    print_action("Clear Artefacts")

    print_step("Checking generated artefacts")
    print_detail(f"Analysis run folders: {analysis_run_count}")
    print_detail(f"PyInstaller workspace items: {pyinstaller_count}")
    print_detail(f"Python bytecode files: {bytecode_count}")
    print_detail(f"Python cache directories: {cache_count}")
    print_result(f"Total selected: {total_count}")

    print()
    print_step("Preserved locations")
    print_detail(f"Runtime input: {relative_path(RUNTIME_DIR)}")
    print_detail(f"Executable output: {relative_path(DIST_DIR)}")

    if total_count == 0:
        print()
        print_info("No generated artefacts selected for clearing")
        return "skipped"

    if not confirm_clear_artefacts():
        return "cancelled"

    print()
    print_step("Clearing generated artefacts")

    analysis_runs_removed = remove_paths(analysis_run_directories)
    pyinstaller_removed = clear_directory_contents(BUILD_PYINSTALLER_DIR)
    bytecode_removed = remove_paths(bytecode_files)
    cache_removed = remove_paths(cache_directories)

    removed_total = (
        analysis_runs_removed +
        pyinstaller_removed +
        bytecode_removed +
        cache_removed
    )

    print_result(f"Artefacts removed: {removed_total}")

    return "cleared"