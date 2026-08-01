"""
Generates stronger password alternatives.
"""

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+?"


def generate_strong_password(length: int = 16) -> str:
    """Generates a cryptographically random password with a full character mix."""
    if length < 8:
        length = 8

    alphabet = string.ascii_letters + string.digits + SYMBOLS
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c in string.ascii_lowercase for c in pwd)
            and any(c in string.ascii_uppercase for c in pwd)
            and any(c in string.digits for c in pwd)
            and any(c in SYMBOLS for c in pwd)
        ):
            return pwd


def generate_passphrase(word_count: int = 4) -> str:
    """Generates a simple random passphrase from a small built-in word list."""
    words = [
        "orbit", "maple", "harbor", "quartz", "ember", "cobalt", "willow",
        "granite", "falcon", "meadow", "signal", "canyon", "lantern", "ripple",
    ]
    chosen = [secrets.choice(words) for _ in range(word_count)]
    number = secrets.randbelow(90) + 10  # 10-99
    return "-".join(chosen) + f"-{number}"


def strengthen_password(password: str) -> str:
    """
    Takes a weak password and returns a strengthened variant:
    - Ensures at least one of each character type
    - Appends random digits/symbols instead of predictable ones
    """
    result = list(password)

    if not any(c in string.ascii_uppercase for c in result):
        result.insert(0, secrets.choice(string.ascii_uppercase))
    if not any(c in string.digits for c in result):
        result.append(secrets.choice(string.digits))
    if not any(c in SYMBOLS for c in result):
        result.append(secrets.choice(SYMBOLS))

    # Pad up to a safer length if still short
    while len("".join(result)) < 12:
        result.append(secrets.choice(string.ascii_letters + string.digits + SYMBOLS))

    return "".join(result)


def suggest_alternatives(password: str, count: int = 3) -> list[str]:
    suggestions = [strengthen_password(password)]
    suggestions.append(generate_strong_password())
    suggestions.append(generate_passphrase())
    return suggestions[:count]
