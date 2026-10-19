#!/usr/bin/env bash
# Scan Terraform code for misconfigurations with Trivy and keep the result as
# evidence: the raw report with failures and passes, a per-check summary and a
# SHA-256 manifest.
#
# Usage: ./scan-iac.sh [TERRAFORM_DIR] [OUT_DIR]
#   defaults: examples/terraform, evidence/iac
# Needs trivy on PATH (https://trivy.dev).
set -euo pipefail

dir="${1:-examples/terraform}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="${2:-evidence/iac}/$stamp"
mkdir -p "$out"

command -v trivy >/dev/null || { echo "trivy not found: https://trivy.dev" >&2; exit 2; }

start=$(date +%s.%N)
trivy config --quiet --include-non-failures --format json --output "$out/trivy.json" "$dir"
end=$(date +%s.%N)

python3 - "$out" "$start" "$end" <<'PY'
import json, sys
out, start, end = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
report = json.load(open(f"{out}/trivy.json"))
rows = []
for result in report.get("Results", []):
    for m in result.get("Misconfigurations", []):
        rows.append({
            "status": m["Status"], "severity": m["Severity"], "id": m["ID"], "title": m["Title"],
            "resource": (m.get("CauseMetadata") or {}).get("Resource") or "",
        })
failed = [r for r in rows if r["status"] == "FAIL"]
summary = {"checks": len(rows), "failed": len(failed), "seconds": round(end - start, 1), "failures": failed}
json.dump(summary, open(f"{out}/summary.json", "w"), indent=1)
print(f"{len(rows)} checks, {len(failed)} failed, {summary['seconds']} s")
for r in sorted(failed, key=lambda r: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(r["severity"])):
    print(f"  {r['severity']:8} {r['id']}  {r['resource']:28} {r['title']}")
PY

(cd "$out" && sha256sum trivy.json summary.json > manifest.sha256)
echo "evidence: $out"
