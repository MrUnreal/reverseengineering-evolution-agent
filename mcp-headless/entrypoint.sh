#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TARGET_FILENAME:-}" ]]; then
  echo "[mcp-headless] TARGET_FILENAME must be set (file must exist in /samples)" >&2
  exit 2
fi

TARGET_PATH="/samples/${TARGET_FILENAME}"
if [[ ! -f "$TARGET_PATH" ]]; then
  echo "[mcp-headless] Target file not found: $TARGET_PATH" >&2
  exit 3
fi

PROJECT_NAME="${PROJECT_NAME:-re_project}"
IMPORT_BASENAME="${IMPORT_BASENAME:-${TARGET_FILENAME}}"
MCP_HOST="${MCP_HOST:-0.0.0.0}"
MCP_PORT="${MCP_PORT:-8080}"
WAIT_SECONDS="${WAIT_SECONDS:-900}"

echo "[mcp-headless] Starting analyzeHeadless for ${TARGET_PATH}"
echo "[mcp-headless] Project: ${PROJECT_NAME}, MCP: ${MCP_HOST}:${MCP_PORT}, hold=${WAIT_SECONDS}s"

"${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" \
  /data/ghidra_projects \
  "${PROJECT_NAME}" \
  -import "${TARGET_PATH}" \
  -overwrite \
  -scriptPath "/opt/ghidra_scripts" \
  -preScript "GAMCPStartServerScript.java" "host=${MCP_HOST}" "port=${MCP_PORT}" \
  -postScript "HoldMcpServerScript.java" "wait_seconds=${WAIT_SECONDS}"

echo "[mcp-headless] analyzeHeadless finished"
