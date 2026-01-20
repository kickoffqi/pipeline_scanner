# Local Scan Test Cases

These minimal workflow YAML files are designed to trigger specific controls.

## How to scan a local file

Example (L1):

```bash
curl -s -X POST http://localhost:5001/api/scan   -H "Content-Type: application/json"   -d "$(jq -n --arg wf "$(cat case-l1-01-tag.yml)"     '{level:"L1", file_path:"case-l1-01-tag.yml", workflow:$wf}')" | jq
```

Example (L2):

```bash
curl -s -X POST http://localhost:5001/api/scan   -H "Content-Type: application/json"   -d "$(jq -n --arg wf "$(cat case-l2-09-azure-oidc-good.yml)"     '{level:"L2", file_path:"case-l2-09-azure-oidc-good.yml", workflow:$wf}')" | jq
```
