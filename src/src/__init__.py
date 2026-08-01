"""
Individual password rule checks.
Each check returns a tuple: (passed: bool, message: str)
"""

import re
import string
from pathlib import Path

MIN_LENGTH = 8
IDEAL_LENGTH = 12

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
COMMON_PASSWORDS_FILE = DATA_DIR / "common_passwords.txt"


def check_length(password: str) -> tuple[bool, str]:
    if len(password) < MIN_LENGTH:
        return False, f"Password is shorter than the minimum of {MIN_LENGTH} characters."
    if len(password) < IDEAL_LENGTH:
        return True, f"Password meets the minimum length but {IDEAL_LENGTH}+ is recommended."
    return True, "Password length is good."


def check_complexity(password: str) -> tuple[bool, str]:
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    missing = []
    if not has_lower:
        missing.append("lowercase letter")
    if not has_upper:
        missing.append("uppercase letter")
    if not has_digit:
        missing.append("digit")
    if not has_symbol:
        missing.append("symbol")

    if missing:
        return False, "Missing: " + ", ".join(missing) + "."
    return True, "Password uses a good mix of character types."


def check_uniqueness(password: str) -> tuple[bool, str]:
    """Flags repeated characters/substrings and simple sequential runs."""
    # 3+ identical characters in a row (e.g. "aaa")
    if re.search(r"(.)\1{2,}", password):
        return False, "Contains 3+ repeated characters in a row (e.g. 'aaa')."

    # Repeated short substrings (e.g. "abcabc", "1212")
    for size in (2, 3, 4):
        for i in range(len(password) - size * 2 + 1):
            chunk = password[i:i + size]
            if password[i + size:i + size * 2] == chunk:
                return False, f"Contains a repeated pattern ('{chunk}{chunk}')."

    # Sequential ascending/descending runs, e.g. "1234", "abcd", "4321"
    sequences = [string.ascii_lowercase, string.digits, "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    lowered = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 3):
            run = seq[i:i + 4]
            if run in lowered or run[::-1] in lowered:
                return False, f"Contains a sequential run ('{run}')."

    return True, "No obvious repeated or sequential patterns found."


def _load_common_passwords() -> set[str]:
    if not COMMON_PASSWORDS_FILE.exists():
        return set()
    with open(COMMON_PASSWORDS_FILE, "r", encoding="utf-8") as f:
        return {line.strip().lower() for line in f if line.strip()}


def check_common_password(password: str) -> tuple[bool, str]:
    common = _load_common_passwords()
    if password.lower() in common:
        return False, "This password appears in a list of commonly used/leaked passwords."
    return True, "Password is not in the common password list."


ALL_CHECKS = [check_length, check_complexity, check_uniqueness, check_common_password]
