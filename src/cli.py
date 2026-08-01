"""
Command-line entry point for the Password Strength Analyzer.

Usage:
    python -m src.cli
    python -m src.cli --password "myTestPass123!"
    python -m src.cli --password "myTestPass123!" --check-breach
"""

import argparse
import getpass

from src.analyzer import analyze_password
from src.suggestions import suggest_alternatives
from src.breach_check import check_pwned


def print_report(password: str, check_breach: bool) -> None:
    result = analyze_password(password)

    print("\n" + "=" * 50)
    print(f"Strength: {result['label']}  (score {result['score']}/4)")
    print(f"Length: {result['password_length']} chars | Entropy: {result['entropy_bits']} bits")
    print("=" * 50)

    if result["passed"]:
        print("\nPassed checks:")
        for msg in result["passed"]:
            print(f"  [OK] {msg}")

    if result["failed"]:
        print("\nIssues found:")
        for msg in result["failed"]:
            print(f"  [!!] {msg}")

    if check_breach:
        breach = check_pwned(password)
        print("\nBreach check:")
        if breach["checked"] and breach["pwned"]:
            print(f"  [!!] {breach['note']} (seen {breach['times_seen']} times)")
        elif breach["checked"]:
            print(f"  [OK] {breach['note']}")
        else:
            print(f"  [--] {breach['note']}")

    if result["label"] in ("Very Weak", "Weak", "Fair"):
        print("\nSuggested stronger alternatives:")
        for alt in suggest_alternatives(password):
            print(f"  -> {alt}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("--password", help="Password to analyze (skips the hidden prompt).")
    parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Also check the password against the Have I Been Pwned database (needs internet).",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter a password to analyze: ")
    print_report(password, args.check_breach)


if __name__ == "__main__":
    main()
