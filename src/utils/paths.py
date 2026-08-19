"""
Shared Remetria project paths.

Defines root-relative paths used by the analysis workflow, exporter, reporter
and cleaner.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys


# ------------------------------------------------------------
# ROOT PATHS
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
SRC_DIR = ROOT_DIR / "src"

DATA_DIR = ROOT_DIR / "data"
RUNTIME_DIR = DATA_DIR / "runtime"

RESULTS_DIR = ROOT_DIR / "results"

BUILD_DIR = ROOT_DIR / "build"
DIST_DIR = ROOT_DIR / "dist"


# ------------------------------------------------------------
# PATH FORMATTING
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a project-relative Windows-style path."""

    try:
        relative = path.relative_to(ROOT_DIR)
    except ValueError:
        relative = path

    return str(relative).replace("/", "\\")


# ------------------------------------------------------------
# TIMESTAMP HELPERS
# ------------------------------------------------------------

def get_utc_timestamp() -> datetime:
    """Return the current UTC timestamp."""

    return datetime.now(timezone.utc)


def build_analysis_run_id(timestamp: datetime) -> str:
    """Return a timestamped Remetria analysis run ID."""

    return f"analysis_{timestamp.strftime('%Y%m%d_%H%M%S')}"


# ------------------------------------------------------------
# DIRECTORY HELPERS
# ------------------------------------------------------------

def ensure_required_directories() -> None:
    """Ensure required Remetria project directories exist."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    DIST_DIR.mkdir(parents=True, exist_ok=True)


def ensure_results_directory() -> None:
    """
    Ensure the results root exists.

    Timestamped analysis subfolders are created by remetria.exporter.
    This function must not create results\\json, results\\tables or
    results\\reports.
    """

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)