#!/bin/bash
set -euo pipefail

# Inputs
export GITHUB_WORKSPACE="C:/Users/rushi/OneDrive/Desktop/drave-external-test"
export INPUT_RULE_PATHS="detections"
export INPUT_API_KEY="test-key"
export INPUT_API_URL="https://drave-bfsi.onrender.com"

cd "$GITHUB_WORKSPACE"

# Exact logic from entrypoint.sh (with /engine replaced for local run)
RULE_PATHS="${INPUT_RULE_PATHS:-detections/rules}"
export DRAVE_API_KEY="$INPUT_API_KEY"
export API_BASE_URL="$INPUT_API_URL"

RULE_FILES=$(find "$RULE_PATHS" -name '*.yml' -o -name '*.yaml' 2>/dev/null || true)
WORKSPACE_DIR="${GITHUB_WORKSPACE:-$PWD}"

TOTAL=0
PASSED=0
FAILED=0
SYNCED=0
SYNC_FAILED=0

for file in $RULE_FILES; do
  TOTAL=$((TOTAL + 1))
  
  if [[ "$file" = /* ]]; then
    ABS_PATH="$file"
  else
    ABS_PATH="${WORKSPACE_DIR}/${file#./}"
    ABS_PATH="${ABS_PATH//\/\///}"
  fi

  echo "  Validating: $ABS_PATH"

  # Replacing /engine with actual local engine path
  if (cd "C:/Users/rushi/OneDrive/Desktop/DRAVE" && uv run drave ci-check "$ABS_PATH"); then
    PASSED=$((PASSED + 1))
    echo "✅ Validation passed for $file"
  else
    FAILED=$((FAILED + 1))
    echo "❌ Validation failed for $file"
  fi

  # Step 2
  if (cd "C:/Users/rushi/OneDrive/Desktop/DRAVE" && uv run python -m cli.sync "$ABS_PATH"); then
    SYNCED=$((SYNCED + 1))
    echo "✅ Synced $file to DRAVE API"
  else
    SYNC_FAILED=$((SYNC_FAILED + 1))
    echo "❌ Failed to sync $file to DRAVE API"
  fi
done

echo "TOTAL=$TOTAL, PASSED=$PASSED, FAILED=$FAILED, SYNCED=$SYNCED, SYNC_FAILED=$SYNC_FAILED"
