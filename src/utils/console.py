"""
Remetria console output helpers.

Keeps analyser output consistent across the launcher and Python workflow.
"""

from __future__ import annotations

import sys


# ------------------------------------------------------------
# BANNER
# ------------------------------------------------------------

REMETRIA_LOGO = r"""
 /███████  /████████ /██      /██ /████████ /████████ /███████  /██████  /██████ 
| ██__  ██| ██_____/| ███    /███| ██_____/|__  ██__/| ██__  ██|_  ██_/ /██__  ██
| ██  \ ██| ██      | ████  /████| ██         | ██   | ██  \ ██  | ██  | ██  \ ██
| ███████/| █████   | ██ ██/██ ██| █████      | ██   | ███████/  | ██  | ████████
| ██__  ██| ██__/   | ██  ███| ██| ██__/      | ██   | ██__  ██  | ██  | ██__  ██
| ██  \ ██| ██      | ██\  █ | ██| ██         | ██   | ██  \ ██  | ██  | ██  | ██
| ██  | ██| ████████| ██ \/  | ██| ████████   | ██   | ██  | ██ /██████| ██  | ██
|__/  |__/|________/|__/     |__/|________/   |__/   |__/  |__/|______/|__/  |__/
"""


def get_logo_width() -> int:
    """Return the maximum printable logo line width."""

    return max(len(line.rstrip()) for line in REMETRIA_LOGO.splitlines() if line.strip())


def print_banner() -> None:
    """Print the Remetria startup banner."""

    print()
    print(REMETRIA_LOGO.rstrip())
    print()
    print("Windows Patch-Remediation Analyser")
    print()
    print("=" * get_logo_width())
    print()


def print_menu_title() -> None:
    """Print the compact menu title used after actions complete."""

    print()
    print("Remetria")
    print("-" * len("Remetria"))


# ------------------------------------------------------------
# PROMPTS
# ------------------------------------------------------------

def prompt_main_menu() -> str:
    """Print the main menu and return an Enter-confirmed selection."""

    print("1. Run Analysis")
    print("2. Clear Artefacts")
    print("3. Exit")
    print()

    return input("Select option [1-3]: ").strip().lower()


# ------------------------------------------------------------
# SECTION HEADERS
# ------------------------------------------------------------

def print_action(title: str) -> None:
    """Print a selected main menu action header."""

    print()
    print(title)
    print("=" * len(title))


def print_section(title: str) -> None:
    """Print an internal workflow section header."""

    print()
    print(title)
    print("-" * len(title))


# ------------------------------------------------------------
# STATUS LINES
# ------------------------------------------------------------

def print_step(message: str) -> None:
    """Print a primary workflow action."""

    print(f"[*] {message}")


def print_result(message: str) -> None:
    """Print an indented workflow result."""

    print(f"    [+] {message}")


def print_detail(message: str) -> None:
    """Print an indented workflow detail."""

    print(f"    [i] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""

    print(f"[!] {message}")


def print_error(message: str) -> None:
    """Print an error message to stderr."""

    print(f"[X] {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """Print a standalone informational message."""

    print(f"[i] {message}")


def print_success(message: str) -> None:
    """Print a standalone success message."""

    print(f"[+] {message}")