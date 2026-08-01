# Password Strength Analyzer

A command-line tool that evaluates the strength of user-entered passwords, checking length, complexity, and uniqueness, then suggests stronger alternatives. Optionally checks passwords against the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) breach database using k-anonymity, so the real password is never sent over the network.

## Features

- **Length & complexity checks** — flags short passwords and missing character types (upper/lower/digit/symbol)
- **Uniqueness checks** — flags repeated characters and sequential runs (`1234`, `qwerty`)
- **Common password check** — flags passwords found in a bundled list of commonly leaked passwords
- **Entropy-based scoring** — rates passwords Very Weak → Very Strong
- **Suggestions** — generates stronger alternatives (random password or passphrase) when a password is weak
- **Optional breach check** — queries the Have I Been Pwned Pwned Passwords API

## Installation

\`\`\`bash
git clone https://github.com/<your-username>/password-strength-analyzer.git
cd password-strength-analyzer
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
\`\`\`

## Usage

Interactive (hidden input):
\`\`\`bash
python -m src.cli
\`\`\`

Non-interactive, with breach check:
\`\`\`bash
python -m src.cli --password "Tr0ub4dor&3" --check-breach
\`\`\`

## Running Tests

\`\`\`bash
pytest -v
\`\`\`

## What This Project Covers

- **Entropy**: why a longer, more random password beats a short "complex-looking" one
- **Hashing (SHA-1)**: how the breach check compares passwords without ever transmitting the real password (HIBP k-anonymity model)
- **Common attack patterns**: dictionary attacks and credential stuffing, and why uniqueness/breach checks matter beyond raw complexity rules

## Project Structure

\`\`\`
password-strength-analyzer/
├── src/
│   ├── rules.py         # length / complexity / uniqueness / common-password checks
│   ├── analyzer.py      # entropy calculation + overall scoring
│   ├── suggestions.py   # generates stronger alternatives
│   ├── breach_check.py  # optional Have I Been Pwned integration
│   └── cli.py           # command-line entry point
├── data/
│   └── common_passwords.txt
├── tests/
└── .github/workflows/ci.yml
\`\`\`

## License

MIT
