"""
Remetria path helpers.

Centralises project paths used by the analyser, loader, exporter, reporter,
cleaner and build workflow.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------------
# PROJECT ROOT
# ------------------------------------------------------------

def get_root_dir() -> Path:
    """
    Return the Remetria project root directory.

    Source mode:
        src/remetria/analyser.py

    Executable mode:
        dist/remetria.exe
    """

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parents[1]

    return Path(__file__).resolve().parents[2]


ROOT_DIR = get_root_dir()


# ------------------------------------------------------------
# PROJECT PATHS
# ------------------------------------------------------------

SRC_DIR = ROOT_DIR / "src"
REMETRIA_DIR = SRC_DIR / "remetria"
PROCESSING_DIR = SRC_DIR / "processing"
UTILS_DIR = SRC_DIR / "utils"

DATA_DIR = ROOT_DIR / "data"
RUNTIME_DIR = DATA_DIR / "runtime"

RESULTS_DIR = ROOT_DIR / "results"

BUILD_DIR = ROOT_DIR / "build"
BUILD_PYINSTALLER_DIR = BUILD_DIR / "pyinstaller"

DIST_DIR = ROOT_DIR / "dist"


# ------------------------------------------------------------
# RUN IDENTIFIERS
# ------------------------------------------------------------

def get_utc_timestamp() -> datetime:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc)


def build_analysis_run_id(timestamp: datetime) -> str:
    """Return a timestamped Remetria analysis run identifier."""

    return timestamp.strftime("analysis_%Y%m%d_%H%M%S")


# ------------------------------------------------------------
# PATH DISPLAY
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a project-relative path for clean console output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


# ------------------------------------------------------------
# REQUIRED DIRECTORY VALIDATION
# ------------------------------------------------------------

def get_required_directories() -> list[Path]:
    """Return directories required by the analyser workflow."""

    return [
        SRC_DIR,
        REMETRIA_DIR,
        PROCESSING_DIR,
        UTILS_DIR,
        DATA_DIR,
        RUNTIME_DIR,
        RESULTS_DIR,
    ]


def ensure_required_directories() -> None:
    """Validate that required project directories exist."""

    missing_directories = [
        relative_path(directory)
        for directory in get_required_directories()
        if not directory.exists()
    ]

    if missing_directories:
        missing = ", ".join(missing_directories)
        raise RuntimeError(f"Missing required directory/directories: {missing}")


def ensure_results_directory() -> None:
    """Create the results directory if it does not exist."""

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)