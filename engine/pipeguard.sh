#!/bin/bash

echo "======================================"
echo " PIPEGUARD – CI/CD SECURITY ENFORCER "
echo "======================================"

BASE_DIR=$(pwd)
REPORTS="$BASE_DIR/reports"
mkdir -p "$REPORTS"

FAILED=0

echo "[1] Secrets Scan"
gitleaks detect --source . --report-path "$REPORTS/secrets.json" --exit-code 1 || FAILED=1

echo "[2] SAST Scan"
semgrep scan --config=auto --json -o "$REPORTS/sast.json" || FAILED=1

echo "[3] CVE Scan"
trivy fs . \
  --scanners vuln \
  --severity HIGH,CRITICAL \
  --timeout 10m \
  --skip-dirs .git,.github,venv \
  --exit-code 1 \
  -o "$REPORTS/trivy.txt" || FAILED=1


echo "[4] IaC Scan"
trivy config . --severity HIGH,CRITICAL --exit-code 1 -o "$REPORTS/iac.txt" || FAILED=1

TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
STATUS="PASS"
[ $FAILED -eq 1 ] && STATUS="FAIL"

cat <<EOF > "$REPORTS/summary.json"
{
  "timestamp": "$TIMESTAMP",
  "status": "$STATUS"
}
EOF

jq ". += [$(cat "$REPORTS/summary.json")]" \
   "$REPORTS/history.json" > "$REPORTS/tmp.json" \
   && mv "$REPORTS/tmp.json" "$REPORTS/history.json"

echo "--------------------------------------"
if [ "$STATUS" = "FAIL" ]; then
  echo "❌ PIPELINE BLOCKED"
  exit 1
else
  echo "✅ PIPELINE PASSED"
fi
