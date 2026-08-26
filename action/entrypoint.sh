#!/bin/bash
# ──────────────────────────────────────────────────────────────
# DRAVE Action Entrypoint
#
# Runs `drave ci-check` against the customer's rule files,
# then syncs results to the DRAVE SaaS API via cli/sync.py.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

# ── Inputs (set by GitHub Actions from action.yml) ──
RULE_PATHS="${INPUT_RULE_PATHS:-detections/rules}"
API_KEY="${INPUT_API_KEY:-}"
API_URL="${INPUT_API_URL:-https://drave-bfsi.onrender.com}"

if [ -z "$API_KEY" ]; then
  echo "::error::DRAVE_API_KEY is required. Generate one from the DRAVE Dashboard → API Keys & Integrations."
  exit 1
fi

# Export for cli/sync.py
export DRAVE_API_KEY="$API_KEY"
export API_BASE_URL="$API_URL"

# ── Discover rule files ──
RULE_FILES=$(find "$RULE_PATHS" -name '*.yml' -o -name '*.yaml' 2>/dev/null || true)

if [ -z "$RULE_FILES" ]; then
  echo "::warning::No YAML rule files found in $RULE_PATHS"
  exit 0
fi

TOTAL=0
PASSED=0
FAILED=0
SYNCED=0
SYNC_FAILED=0

echo "═══════════════════════════════════════════════════"
echo "  DRAVE Detection Validation Engine"
echo "═══════════════════════════════════════════════════"
echo ""

for file in $RULE_FILES; do
  TOTAL=$((TOTAL + 1))
  echo "──────────────────────────────────────────────"
  echo "  Validating: $file"
  echo "──────────────────────────────────────────────"

  # Step 1: Run real evidence computation via ci-check
  if uv run drave ci-check "$file"; then
    PASSED=$((PASSED + 1))
    echo "✅ Validation passed for $file"
  else
    FAILED=$((FAILED + 1))
    echo "::warning file=$file::Validation failed for $file (hard gates not passed)"
    # Don't exit — continue processing other rules, but sync anyway
    # so the dashboard shows the real failing evidence
  fi

  # Step 2: Sync to DRAVE SaaS API (real evidence, not hardcoded)
  echo "  → Syncing evidence to DRAVE API..."
  if uv run python -m cli.sync "$file"; then
    SYNCED=$((SYNCED + 1))
    echo "✅ Synced $file to DRAVE API"
  else
    SYNC_FAILED=$((SYNC_FAILED + 1))
    echo "::warning file=$file::Failed to sync $file to DRAVE API"
  fi

  echo ""
done

echo "═══════════════════════════════════════════════════"
echo "  Summary"
echo "═══════════════════════════════════════════════════"
echo "  Total rules:       $TOTAL"
echo "  Validation passed: $PASSED"
echo "  Validation failed: $FAILED"
echo "  Synced to API:     $SYNCED"
echo "  Sync failures:     $SYNC_FAILED"
echo "═══════════════════════════════════════════════════"

# Set outputs for downstream workflow steps
echo "total=$TOTAL" >> "$GITHUB_OUTPUT"
echo "passed=$PASSED" >> "$GITHUB_OUTPUT"
echo "failed=$FAILED" >> "$GITHUB_OUTPUT"
echo "synced=$SYNCED" >> "$GITHUB_OUTPUT"

# Exit non-zero if any validation failed
if [ "$FAILED" -gt 0 ]; then
  echo "::error::$FAILED rule(s) failed hard gate validation."
  exit 1
fi
