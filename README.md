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

## Flask API

Run the web API:

```bash
export FLASK_APP=wsgi.py
export FLASK_DEBUG=1
flask run --host 0.0.0.0 --port 5000
```

See `docs/api.md` for endpoint details.


## API filters

You can filter findings by status:

```bash
curl -s -X POST http://localhost:5001/api/scan \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg wf \"$(cat .github/workflows/ci.yml)\" '{level:\"L1\", file_path:\"ci.yml\", workflow:$wf, only_status:[\"FAIL\",\"WARN\"]}')" | jq
```

## Scan from POST API:
curl -s -X POST "http://localhost:5001/api/scan" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg wf 'name: CI
on: [push]
permissions:
  contents: read
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
' '{level:"L1", file_path:"ci.yml", workflow:$wf}')" | jq

## Scan from Upload Files
curl -s -X POST http://localhost:5001/api/scan/file \
  -F level=L1 \
  -F only_status=fail,warn \
  -F file=@./test/local-scan-test-workflow.yml | jq

## With file path
curl -s -X POST http://localhost:5001/api/scan/file \
  -F level=L1 \
  -F file_path=ci.yml \
  -F file=@.github/workflows/ci.yml | jq

## Policy as Josn format
curl -s -X POST http://localhost:5001/api/scan/file \
  -F level=L1 \
  -F policy='{"levels":{"L1":{"controls":{"L1-01":{"allow_tags":true}}}}}' \
  -F file=@.github/workflows/ci.yml | jq