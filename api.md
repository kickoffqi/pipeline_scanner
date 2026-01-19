# Web API (Flask)

This project includes a minimal Flask API wrapper around the scanner core.

## Run (dev)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export FLASK_APP=wsgi.py
export FLASK_DEBUG=1
flask run --host 0.0.0.0 --port 5000
```

## Endpoints

### `GET /api/health`

Response:

```json
{"status":"ok"}
```

### `POST /api/policy/validate`

Request:

```json
{
  "allow_semver_tags": false,
  "require_explicit_permissions": true
}
```

Response:

```json
{
  "valid": true,
  "policy": { ...normalized... }
}
```

### `POST /api/scan`

Request:

```json
{
  "workflow": "name: CI\non: [push]\njobs: ...",
  "file_path": "ci.yml",
  "level": "L2",
  "policy": {
    "allow_semver_tags": false
  }
}
```

Response:

```json
{
  "level": "L2",
  "findings": [ ... ]
}
```

Notes:
- `policy` is optional. If omitted, defaults apply based on `level`.
- Requests are limited by `MAX_REQUEST_BYTES` (default 1MB).
