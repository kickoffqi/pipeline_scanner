# GitHub Actions Pipeline Security Scanner (MVP)

This repository contains a Python-based scanner that parses GitHub Actions workflow YAML,
builds an Intermediate Representation (IR), derives effective fields, and evaluates controls.

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m scanner.cli scan .github/workflows
```

## Output

The scanner prints JSON results to stdout and exits non-zero if any `FAIL` findings exist.


## Implemented Controls (MVP)

- L1-01 Action Pin
- L1-02 Explicit Permissions
- L1-03 Unsafe pull_request_target
- L1-04 Fork PR Secrets

- L2-09 Azure Authentication via OIDC

## Policy Configuration

Use YAML for policy configuration (recommended):

```bash
python -m scanner.cli scan .github/workflows --policy policy.example.yml
```

## Explainability

Each finding includes an `explain` object with `why`, `detect`, `fix`, `verify`, and `difficulty` fields to help engineers understand and remediate issues.

## SARIF Output (GitHub Code Scanning)

Generate SARIF for GitHub code scanning:

```bash
python -m scanner.cli scan .github/workflows --policy policy.example.yml --format sarif --out results.sarif
```

## Levels (L1/L2/L3)

Evaluate different security levels:

```bash
python -m scanner.cli scan .github/workflows --level L1
python -m scanner.cli scan .github/workflows --level L2
```

## Level-based Default Policy

Each level applies different default policy values (stricter at higher levels). A user policy file overrides these defaults.

Examples:
- L1 allows semver tags for actions (WARN)
- L2+ requires SHA pinning and forbids Azure auth on PR triggers by default
