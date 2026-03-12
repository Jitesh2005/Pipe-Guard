#!/bin/bash

echo "======================================"
echo " PIPEGUARD – CI/CD SECURITY ENFORCER "
echo "======================================"

BASE_DIR=$(pwd)
REPORTS="$BASE_DIR/reports"
mkdir -p "$REPORTS"

FAILED=0

########################################
# Clean old reports
########################################
rm -f "$REPORTS/secrets.json"
rm -f "$REPORTS/sast.json"
rm -f "$REPORTS/trivy.txt"
rm -f "$REPORTS/iac.txt"

########################################
# 1️⃣ Secrets Scan (Gitleaks)
########################################
echo "[1] Secrets Scan"

gitleaks detect \
--source . \
--no-git \
--report-path "$REPORTS/secrets.json" \
--exit-code 1 || FAILED=1

if [ -f "$REPORTS/secrets.json" ]; then
  SECRETS_FOUND=$(jq length "$REPORTS/secrets.json")

  if [ "$SECRETS_FOUND" -gt 0 ]; then
    echo "❌ Secrets detected: $SECRETS_FOUND"
    FAILED=1
  else
    echo "✅ No secrets found"
  fi
else
  echo "✅ No secrets found"
fi


########################################
# 2️⃣ SAST Scan (Semgrep)
########################################
echo "[2] SAST Scan"

semgrep scan \
--config=auto \
--exclude reports \
--json \
-o "$REPORTS/sast.json" || FAILED=1


########################################
# 3️⃣ CVE Scan (Trivy)
########################################
echo "[3] CVE Scan"

trivy fs . \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --timeout 10m \
  --skip-dirs .git,.github,venv,backend/venv,reports \
  --exit-code 1 \
  -o "$REPORTS/trivy.txt" || FAILED=1


########################################
# 4️⃣ IaC Misconfiguration Scan
########################################
echo "[4] IaC Scan"

trivy config . \
  --severity HIGH,CRITICAL \
  --skip-dirs reports \
  --exit-code 1 \
  -o "$REPORTS/iac.txt" || FAILED=1


########################################
# 5️⃣ Pipeline Decision
########################################

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
STATUS="PASS"

if [ $FAILED -eq 1 ]; then
  STATUS="FAIL"
fi


########################################
# 6️⃣ Summary Report
########################################

cat <<EOF > "$REPORTS/summary.json"
{
  "timestamp": "$TIMESTAMP",
  "status": "$STATUS",
  "risk_score": $RISK_SCORE,
  "secrets": $SECRETS_COUNT,
  "sast": $SAST_COUNT,
  "cve": $CVE_COUNT,
  "iac": $IAC_COUNT
}
EOF


########################################
# 7️⃣ History Tracking
########################################

if [ ! -f "$REPORTS/history.json" ]; then
  echo "[]" > "$REPORTS/history.json"
fi

jq ". += [$(cat "$REPORTS/summary.json")]" \
"$REPORTS/history.json" > "$REPORTS/tmp.json" \
&& mv "$REPORTS/tmp.json" "$REPORTS/history.json"


########################################
# 8️⃣ Final Result
########################################

echo "--------------------------------------"

if [ "$STATUS" = "FAIL" ]; then
  echo "❌ PIPELINE BLOCKED"
  exit 1
else
  echo "✅ PIPELINE PASSED"
fi


########################################
# 5️⃣ Risk Score Calculation
########################################

S########################################
# 5️⃣ Risk Score Calculation
########################################

SECRETS_COUNT=$(jq length "$REPORTS/secrets.json" 2>/dev/null || echo 0)
SAST_COUNT=$(jq '.results | length' "$REPORTS/sast.json" 2>/dev/null || echo 0)

CVE_COUNT=$(grep -c "CRITICAL" "$REPORTS/trivy.txt" 2>/dev/null || echo 0)
IAC_COUNT=$(grep -c "HIGH" "$REPORTS/iac.txt" 2>/dev/null || echo 0)

# Default value
RISK_SCORE=0

if [ "$SECRETS_COUNT" -gt 0 ]; then
  RISK_SCORE=$((RISK_SCORE + 40))
fi

if [ "$CVE_COUNT" -gt 0 ]; then
  RISK_SCORE=$((RISK_SCORE + 30))
fi

if [ "$SAST_COUNT" -gt 0 ]; then
  RISK_SCORE=$((RISK_SCORE + 10))
fi

if [ "$IAC_COUNT" -gt 0 ]; then
  RISK_SCORE=$((RISK_SCORE + 20))
fi

echo "Risk Score: $RISK_SCORE / 100"


########################################
# 6️⃣ Security Policy Enforcement
########################################

POLICY_FILE="policy.json"

SECRETS_LIMIT=$(jq '.secrets' $POLICY_FILE)
CVE_LIMIT=$(jq '.critical_cve' $POLICY_FILE)
SAST_LIMIT=$(jq '.sast' $POLICY_FILE)
IAC_LIMIT=$(jq '.iac' $POLICY_FILE)

if [ "$SECRETS_COUNT" -gt "$SECRETS_LIMIT" ]; then
  echo "❌ Policy Violation: Secrets detected"
  FAILED=1
fi

if [ "$CVE_COUNT" -gt "$CVE_LIMIT" ]; then
  echo "❌ Policy Violation: Critical CVE detected"
  FAILED=1
fi

if [ "$SAST_COUNT" -gt "$SAST_LIMIT" ]; then
  echo "❌ Policy Violation: Too many SAST issues"
  FAILED=1
fi

if [ "$IAC_COUNT" -gt "$IAC_LIMIT" ]; then
  echo "❌ Policy Violation: IaC misconfigurations"
  FAILED=1
fi
