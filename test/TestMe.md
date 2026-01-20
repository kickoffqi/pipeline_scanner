## Test cases
L1-01 Action Pinning
	•	case-l1-01-tag.yml：uses: ...@vX（典型 WARN）
	•	case-l1-01-sha.yml：uses: ...@<sha>（结构上 PASS；你可换成真实 SHA）

L1-02 Permissions
	•	case-l1-02-implicit.yml：没有任何 permissions:（触发 implicit → FAIL）
	•	case-l1-02-broad-write.yml：workflow 级别 write（触发 broad perms → FAIL/WARN）

L1-03 pull_request_target
	•	case-l1-03-pr-target-risky.yml：pull_request_target + 写权限（触发 FAIL/WARN）
	•	case-l1-03-pr-target-safer.yml：pull_request_target + 只读权限（更安全，PASS/WARN 取决于你的规则）

L1-04 fork PR secrets
	•	case-l1-04-fork-pr-secrets.yml：pull_request + env: ${{ secrets... }}（触发 FAIL/WARN）

L2-09 Azure OIDC
	•	case-l2-09-azure-oidc-good.yml：id-token: write + azure/login@v2（期望 PASS/WARN）
	•	case-l2-09-azure-oidc-missing-idtoken.yml：缺 id-token: write 但使用 azure/login@v2（期望 FAIL）

## How to run
    ## L1:
        curl -s -X POST http://localhost:5001/api/scan \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg wf "$(cat ./test/scan-test-cases/case-l1-01-tag.yml)" \
            '{level:"L1", file_path:"case-l1-01-tag.yml", workflow:$wf}')" | jq

    ## L2:
        curl -s -X POST http://localhost:5001/api/scan \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg wf "$(cat ./test/scan-test-cases/case-l2-09-azure-oidc-good.yml)" \
            '{level:"L2", file_path:"case-l2-09-azure-oidc-good.yml", workflow:$wf}')" | jq