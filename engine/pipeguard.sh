#!/bin/bash

echo "======================================"
echo " PIPEGUARD – CI/CD SECURITY ENFORCER "
echo "======================================"

BASE_DIR=$(pwd)
REPORTS="$BASE_DIR/reports"
mkdir -p "$REPORTS"

FAILED=0
REASONS=""

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
--report-path "$REPORTS/secrets.json"

if [ -f "$REPORTS/secrets.json" ]; then
  SECRETS_COUNT=$(jq length "$REPORTS/secrets.json")

  if [ "$SECRETS_COUNT" -gt 0 ]; then
    echo "❌ Secrets detected: $SECRETS_COUNT"
    REASONS="$REASONS\n• Secret detected in repository ($SECRETS_COUNT found)"
    FAILED=1
  else
    echo "✅ No secrets found"
  fi
else
  SECRETS_COUNT=0
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
-o "$REPORTS/sast.json"

if [ -f "$REPORTS/sast.json" ]; then
  SAST_COUNT=$(jq '.results | length' "$REPORTS/sast.json")

  if [ "$SAST_COUNT" -gt 0 ]; then
    echo "❌ SAST findings: $SAST_COUNT"
    REASONS="$REASONS\n• Static code vulnerabilities detected ($SAST_COUNT findings)"
  fi
else
  SAST_COUNT=0
fi

########################################
# 3️⃣ CVE Scan (Trivy)
########################################
echo "[3] CVE Scan"

trivy fs . \
--scanners vuln \
--severity HIGH,CRITICAL \
--timeout 10m \
--skip-dirs .git,.github,venv,backend/venv,reports \
-o "$REPORTS/trivy.txt"

CVE_COUNT=$(grep -c "CRITICAL" "$REPORTS/trivy.txt" 2>/dev/null)
CVE_COUNT=${CVE_COUNT:-0}

if [ "$CVE_COUNT" -gt 0 ]; then
  echo "❌ Critical CVEs detected: $CVE_COUNT"
  REASONS="$REASONS\n• Critical dependency vulnerabilities detected"
fi

########################################
# 4️⃣ IaC Misconfiguration Scan
########################################
echo "[4] IaC Scan"

trivy config . \
--severity HIGH,CRITICAL \
--skip-dirs reports \
-o "$REPORTS/iac.txt"

IAC_COUNT=$(grep -c "HIGH" "$REPORTS/iac.txt" 2>/dev/null)
IAC_COUNT=${IAC_COUNT:-0}

if [ "$IAC_COUNT" -gt 0 ]; then
  echo "❌ IaC misconfigurations detected: $IAC_COUNT"
  REASONS="$REASONS\n• Infrastructure misconfiguration detected"
fi

########################################
# 5️⃣ Risk Score Calculation
########################################

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

########################################
# Pipeline Decision
########################################

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
STATUS="PASS"

if [ $FAILED -eq 1 ]; then
  STATUS="FAIL"
fi

########################################
# Summary Report
########################################

cat <<EOF > "$REPORTS/summary.json"
{
  "timestamp": "$TIMESTAMP",
  "status": "$STATUS",
  "risk_score": $RISK_SCORE,
  "secrets": $SECRETS_COUNT,
  "sast": $SAST_COUNT,
  "cve": $CVE_COUNT,
  "iac": $IAC_COUNT,
  "reasons": "$REASONS_JSON"
}
EOF

########################################
# History Tracking
########################################

if [ ! -f "$REPORTS/history.json" ]; then
  echo "[]" > "$REPORTS/history.json"
fi

jq ". += [$(cat "$REPORTS/summary.json")]" \
"$REPORTS/history.json" > "$REPORTS/tmp.json" \
&& mv "$REPORTS/tmp.json" "$REPORTS/history.json"

########################################
# Final Result
########################################

echo "--------------------------------------"

if [ "$STATUS" = "FAIL" ]; then

  echo ""
  echo "❌ PIPELINE BLOCKED"
  echo ""
  echo "Reasons:"
  echo -e "$REASONS"
  echo ""
  echo "Risk Score: $RISK_SCORE / 100"

  exit 1

else

  echo ""
  echo "✅ PIPELINE PASSED"
  echo ""
  echo "No security issues detected."
  echo ""
  echo "Risk Score: $RISK_SCORE / 100"

fi
