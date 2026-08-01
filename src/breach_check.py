"""
Optional: checks a password against the Have I Been Pwned Pwned Passwords API
using k-anonymity (only a 5-character SHA-1 prefix is ever sent over the network,
so the real password never leaves your machine).

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_pwned(password: str, timeout: int = 5) -> dict:
    """
    Returns: {"checked": bool, "pwned": bool, "times_seen": int, "note": str}
    "checked" is False if the check couldn't be completed (e.g. no internet, no `requests`).
    """
    if not REQUESTS_AVAILABLE:
        return {
            "checked": False,
            "pwned": False,
            "times_seen": 0,
            "note": "The 'requests' library isn't installed; skipping online breach check.",
        }

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(HIBP_API_URL.format(prefix=prefix), timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        return {
            "checked": False,
            "pwned": False,
            "times_seen": 0,
            "note": f"Could not reach the breach-check service ({exc}).",
        }

    for line in response.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return {
                "checked": True,
                "pwned": True,
                "times_seen": int(count),
                "note": "This password has appeared in known data breaches.",
            }

    return {
        "checked": True,
        "pwned": False,
        "times_seen": 0,
        "note": "Not found in the Pwned Passwords database.",
    }
