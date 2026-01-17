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

