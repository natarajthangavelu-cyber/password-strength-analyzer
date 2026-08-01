"""
Combines individual rule checks into an overall strength score/label.
"""

import math
import string

from src.rules import ALL_CHECKS

STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]


def calculate_entropy(password: str) -> float:
    """Rough entropy estimate in bits: length * log2(character pool size)."""
    if not password:
        return 0.0

    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    pool = max(pool, 1)

    return len(password) * math.log2(pool)


def _label_from_score(score: int, failed_common_or_uniqueness: bool) -> str:
    if failed_common_or_uniqueness:
        # A leaked/common or highly patterned password is never "Strong", regardless of entropy
        return STRENGTH_LABELS[min(score, 1)]
    return STRENGTH_LABELS[min(score, len(STRENGTH_LABELS) - 1)]


def analyze_password(password: str) -> dict:
    """
    Runs all rule checks + entropy calculation.
    Returns a dict with: score, label, entropy_bits, passed, failed, reasons
    """
    passed = []
    failed = []

    for check in ALL_CHECKS:
        ok, message = check(password)
        (passed if ok else failed).append(message)

    entropy = calculate_entropy(password)

    # Base score from entropy (bits -> 0-4 scale)
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4

    # Penalize score for each failed rule
    score = max(0, score - len(failed))

    critical_fail = any(
        "common" in msg.lower() or "repeated" in msg.lower() or "sequential" in msg.lower()
        for msg in failed
    )

    label = _label_from_score(score, critical_fail)

    return {
        "password_length": len(password),
        "entropy_bits": round(entropy, 1),
        "score": score,
        "label": label,
        "passed": passed,
        "failed": failed,
    }
