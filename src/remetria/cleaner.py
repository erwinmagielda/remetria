"""
Remetria artefact cleaner.

Removes generated report, table, JSON, build, and Python cache artefacts.
Collected scans, active runtime scans, and executable output are intentionally
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
    COLLECTED_DIR,
    DIST_DIR,
    JSON_DIR,
    REPORTS_DIR,
    ROOT_DIR,
    RUNTIME_DIR,
    TABLES_DIR,
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


def remove_directory_if_exists(path: Path) -> int:
    """Remove a directory if it exists."""

    if not path.exists():
        return 0

    shutil.rmtree(path)
    return 1


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

    cache_directories = find_python_cache_directories()
    bytecode_files = find_python_bytecode_files()

    json_count = count_directory_items(JSON_DIR)
    reports_count = count_directory_items(REPORTS_DIR)
    tables_count = count_directory_items(TABLES_DIR)
    pyinstaller_count = count_directory_items(BUILD_PYINSTALLER_DIR)
    bytecode_count = len(bytecode_files)
    cache_count = len(cache_directories)

    total_count = (
        json_count +
        reports_count +
        tables_count +
        pyinstaller_count +
        bytecode_count +
        cache_count
    )

    print_action("Clear Artefacts")

    print_step("Reviewing generated artefact targets")
    print_result("Clear plan prepared")
    print_detail(f"Generated JSON output: {relative_path(JSON_DIR)}")
    print_detail(f"Generated reports: {relative_path(REPORTS_DIR)}")
    print_detail(f"Generated tables: {relative_path(TABLES_DIR)}")
    print_detail(f"PyInstaller workspace: {relative_path(BUILD_PYINSTALLER_DIR)}")
    print_detail("Python cache directories: __pycache__")
    print_detail("Python bytecode files: *.pyc, *.pyo")

    print()
    print_step("Checking preserved locations")
    print_result("Preserved locations confirmed")
    print_detail(f"Collected archive: {relative_path(COLLECTED_DIR)}")
    print_detail(f"Runtime input workset: {relative_path(RUNTIME_DIR)}")
    print_detail(f"Executable output: {relative_path(DIST_DIR)}")

    print()
    print_step("Counting selected artefacts")
    print_result("Artefact count calculated")
    print_detail(f"Generated JSON items: {json_count}")
    print_detail(f"Generated report items: {reports_count}")
    print_detail(f"Generated table items: {tables_count}")
    print_detail(f"PyInstaller workspace items: {pyinstaller_count}")
    print_detail(f"Python bytecode files: {bytecode_count}")
    print_detail(f"Python cache directories: {cache_count}")
    print_detail(f"Total artefacts selected: {total_count}")

    if total_count == 0:
        print()
        print_info("No generated artefacts selected for clearing")
        return "skipped"

    if not confirm_clear_artefacts():
        return "cancelled"

    print()
    print_step("Clearing selected artefacts")

    json_removed = clear_directory_contents(JSON_DIR)
    reports_removed = clear_directory_contents(REPORTS_DIR)
    tables_removed = clear_directory_contents(TABLES_DIR)
    pyinstaller_removed = clear_directory_contents(BUILD_PYINSTALLER_DIR)
    bytecode_removed = remove_paths(bytecode_files)
    cache_removed = remove_paths(cache_directories)

    print_result("Selected artefacts cleared")
    print_detail(f"Generated JSON items removed: {json_removed}")
    print_detail(f"Generated report items removed: {reports_removed}")
    print_detail(f"Generated table items removed: {tables_removed}")
    print_detail(f"PyInstaller workspace items removed: {pyinstaller_removed}")
    print_detail(f"Python bytecode files removed: {bytecode_removed}")
    print_detail(f"Python cache directories removed: {cache_removed}")

    return "cleared"