#!/bin/bash

# E2E test: Vault secret provider integration
# Run from inside the client-vault pod's client container.
# Verifies that ClawGuard resolves tokens from Vault and injects them correctly.

PASS=0
FAIL=0
TOTAL=0
CURL="curl -s --max-time 5"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

check_replaced() {
  local field="$1"
  local dummy="$2"
  local real="$3"
  local actual="$4"
  TOTAL=$((TOTAL + 2))

  if echo "$actual" | grep -q "$real"; then
    echo -e "    ${GREEN}PASS${NC}  ${field}: Dummy sent ${DIM}[$dummy]${NC} -> Real received ${BOLD}[$real]${NC}"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}FAIL${NC}  ${field}: Dummy sent ${DIM}[$dummy]${NC} -> Expected real ${BOLD}[$real]${NC} but not found"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  fi

  if echo "$actual" | grep -q "$dummy"; then
    echo -e "    ${RED}FAIL${NC}  ${field}: Dummy ${DIM}[$dummy]${NC} leaked through (should have been replaced)"
    FAIL=$((FAIL + 1))
  else
    echo -e "    ${GREEN}PASS${NC}  ${field}: Dummy ${DIM}[$dummy]${NC} correctly removed"
    PASS=$((PASS + 1))
  fi
}

check_method() {
  local expected="$1"
  local actual="$2"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "\"method\": \"$expected\""; then
    echo -e "    ${GREEN}PASS${NC}  Method: ${CYAN}$expected${NC}"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}FAIL${NC}  Method: expected ${CYAN}$expected${NC}"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo -e "${BOLD}ClawGuard Vault Secret Provider E2E Test Suite${NC}"
echo -e "${DIM}================================================${NC}"

# ─── Bearer Auth (token from Vault) ──────────────────────────

echo ""
echo -e "${YELLOW}Bearer Auth via Vault ${DIM}(bearer-api)${NC}"

echo ""
echo -e "  ${CYAN}[GET]${NC} Correct dummy -> Vault-resolved real token"
RES=$($CURL https://bearer-api/resource -H "Authorization: Bearer dummy-bearer-placeholder")
check_replaced "Authorization" "dummy-bearer-placeholder" "Bearer bearer-secret-token-123" "$RES"
check_method "GET" "$RES"

# ─── Header Auth (token from Vault) ─────────────────────────

echo ""
echo -e "${YELLOW}Header Auth via Vault ${DIM}(header-api)${NC}"

echo ""
echo -e "  ${CYAN}[GET]${NC} Correct dummy -> Vault-resolved real key"
RES=$($CURL https://header-api/resource -H "X-API-Key: dummy-header-placeholder")
check_replaced "X-API-Key" "dummy-header-placeholder" "header-secret-key-456" "$RES"
check_method "GET" "$RES"

# ─── Query Param Auth (token from Vault) ────────────────────

echo ""
echo -e "${YELLOW}Query Param Auth via Vault ${DIM}(query-api)${NC}"

echo ""
echo -e "  ${CYAN}[GET]${NC} Correct dummy -> Vault-resolved real param"
RES=$($CURL "https://query-api/resource?api_key=dummy-query-placeholder")
check_replaced "api_key param" "dummy-query-placeholder" "query-secret-token-789" "$RES"
check_method "GET" "$RES"

# ─── Results ────────────────────────────────────────────────

echo ""
echo -e "${DIM}================================================${NC}"
if [ $FAIL -gt 0 ]; then
  echo -e "${RED}Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
  exit 1
else
  echo -e "${GREEN}All $TOTAL tests passed!${NC}"
  exit 0
fi
