#!/bin/bash

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
    echo -e "    ${GREEN}✅ PASS${NC}  ${field}: Dummy sent ${DIM}[$dummy]${NC} → Real received ${BOLD}[$real]${NC}"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  ${field}: Dummy sent ${DIM}[$dummy]${NC} → Expected real ${BOLD}[$real]${NC} but not found"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  fi

  if echo "$actual" | grep -q "$dummy"; then
    echo -e "    ${RED}❌ FAIL${NC}  ${field}: Dummy ${DIM}[$dummy]${NC} leaked through 💀 (should have been replaced)"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  else
    echo -e "    ${GREEN}✅ PASS${NC}  ${field}: Dummy ${DIM}[$dummy]${NC} correctly removed 🧹"
    PASS=$((PASS + 1))
  fi
}

check_injected() {
  local field="$1"
  local real="$2"
  local actual="$3"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "$real"; then
    echo -e "    ${GREEN}✅ PASS${NC}  ${field}: No dummy sent → Real injected ${BOLD}[$real]${NC} 💉"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  ${field}: No dummy sent → Expected real ${BOLD}[$real]${NC} but not found"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  fi
}

check_rejected() {
  local desc="$1"
  local actual="$2"
  local http_code="$3"
  TOTAL=$((TOTAL + 1))

  if [ "$http_code" = "403" ]; then
    echo -e "    ${GREEN}✅ PASS${NC}  ${desc}: Rejected with ${BOLD}403${NC} 🚫"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  ${desc}: Expected ${BOLD}403${NC} but got ${BOLD}$http_code${NC}"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  fi
}

check_no_real_token() {
  local field="$1"
  local real="$2"
  local actual="$3"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "$real"; then
    echo -e "    ${RED}❌ FAIL${NC}  ${field}: Real token ${BOLD}[$real]${NC} leaked in error response 💀"
    FAIL=$((FAIL + 1))
  else
    echo -e "    ${GREEN}✅ PASS${NC}  ${field}: Real token not exposed in rejection 🔒"
    PASS=$((PASS + 1))
  fi
}

check_passthrough() {
  local field="$1"
  local sent="$2"
  local actual="$3"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "$sent"; then
    echo -e "    ${GREEN}✅ PASS${NC}  ${field}: Sent ${DIM}[$sent]${NC} → Received unchanged ${BOLD}[$sent]${NC} 🔀"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  ${field}: Sent ${DIM}[$sent]${NC} → Not found in response (was it modified?)"
    echo -e "          ${DIM}Response: $actual${NC}"
    FAIL=$((FAIL + 1))
  fi
}

check_method() {
  local expected="$1"
  local actual="$2"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "\"method\": \"$expected\""; then
    echo -e "    ${GREEN}✅ PASS${NC}  Method: ${CYAN}$expected${NC}"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  Method: expected ${CYAN}$expected${NC}"
    FAIL=$((FAIL + 1))
  fi
}

check_body() {
  local expected="$1"
  local actual="$2"
  TOTAL=$((TOTAL + 1))

  if echo "$actual" | grep -q "$expected"; then
    echo -e "    ${GREEN}✅ PASS${NC}  Body: payload forwarded correctly 📦"
    PASS=$((PASS + 1))
  else
    echo -e "    ${RED}❌ FAIL${NC}  Body: expected ${DIM}[$expected]${NC} in response"
    FAIL=$((FAIL + 1))
  fi
}

echo ""
echo -e "${BOLD}🛡️  ClawGuard Auth Injection Test Suite${NC}"
echo -e "${DIM}════════════════════════════════════════════════════${NC}"

# ─── Bearer Auth ───────────────────────────────────────────────

echo ""
echo -e "${YELLOW}🔑 Bearer Auth ${DIM}(bearer-api)${NC}"

echo ""
echo -e "  📤 ${CYAN}[GET]${NC} Correct dummy → should be replaced with real token"
RES=$($CURL https://bearer-api/resource -H "Authorization: Bearer dummy-bearer-placeholder")
check_replaced "Authorization" "dummy-bearer-placeholder" "Bearer bearer-secret-token-123" "$RES"
check_method "GET" "$RES"

echo ""
echo -e "  📤 ${CYAN}[POST]${NC} Correct dummy + body → should be replaced, body forwarded"
RES=$($CURL -X POST https://bearer-api/resource \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dummy-bearer-placeholder" \
  -d '{"payload":"test-data"}')
check_replaced "Authorization" "dummy-bearer-placeholder" "Bearer bearer-secret-token-123" "$RES"
check_method "POST" "$RES"
check_body "test-data" "$RES"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} Wrong dummy → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' https://bearer-api/resource -H "Authorization: Bearer wrong-dummy-token")
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Wrong bearer dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "Authorization" "bearer-secret-token-123" "$BODY"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} No token at all → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' https://bearer-api/resource)
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Missing bearer dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "Authorization" "bearer-secret-token-123" "$BODY"

# ─── Header Auth ──────────────────────────────────────────────

echo ""
echo -e "${YELLOW}🏷️  Header Auth ${DIM}(header-api)${NC}"

echo ""
echo -e "  📤 ${CYAN}[GET]${NC} Correct dummy → should be replaced with real key"
RES=$($CURL https://header-api/resource -H "X-API-Key: dummy-header-placeholder")
check_replaced "X-API-Key" "dummy-header-placeholder" "header-secret-key-456" "$RES"
check_method "GET" "$RES"

echo ""
echo -e "  📤 ${CYAN}[POST]${NC} Correct dummy + body → should be replaced, body forwarded"
RES=$($CURL -X POST https://header-api/resource \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dummy-header-placeholder" \
  -d '{"payload":"header-test"}')
check_replaced "X-API-Key" "dummy-header-placeholder" "header-secret-key-456" "$RES"
check_method "POST" "$RES"
check_body "header-test" "$RES"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} Wrong dummy → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' https://header-api/resource -H "X-API-Key: wrong-key")
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Wrong header dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "X-API-Key" "header-secret-key-456" "$BODY"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} No X-API-Key at all → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' https://header-api/resource)
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Missing header dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "X-API-Key" "header-secret-key-456" "$BODY"

# ─── Query Param Auth ─────────────────────────────────────────

echo ""
echo -e "${YELLOW}❓ Query Param Auth ${DIM}(query-api)${NC}"

echo ""
echo -e "  📤 ${CYAN}[GET]${NC} Correct dummy → should be replaced with real param"
RES=$($CURL "https://query-api/resource?api_key=dummy-query-placeholder")
check_replaced "api_key param" "dummy-query-placeholder" "query-secret-token-789" "$RES"
check_method "GET" "$RES"

echo ""
echo -e "  📤 ${CYAN}[POST]${NC} Correct dummy + body → should be replaced, body forwarded"
RES=$($CURL -X POST "https://query-api/resource?api_key=dummy-query-placeholder" \
  -H "Content-Type: application/json" \
  -d '{"payload":"query-test"}')
check_replaced "api_key param" "dummy-query-placeholder" "query-secret-token-789" "$RES"
check_method "POST" "$RES"
check_body "query-test" "$RES"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} Wrong dummy → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' "https://query-api/resource?api_key=wrong-param")
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Wrong query dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "api_key" "query-secret-token-789" "$BODY"

echo ""
echo -e "  🚨 ${CYAN}[GET]${NC} No api_key param → should be REJECTED"
RES=$($CURL -w '\n%{http_code}' https://query-api/resource)
HTTP_CODE=$(echo "$RES" | tail -1)
BODY=$(echo "$RES" | sed '$d')
check_rejected "Missing query dummy" "$BODY" "$HTTP_CODE"
check_no_real_token "api_key" "query-secret-token-789" "$BODY"

# ─── Passthrough (no injection) ───────────────────────────────

echo ""
echo -e "${YELLOW}🔀 Passthrough ${DIM}(passthrough-api — unconfigured host)${NC}"

echo ""
echo -e "  📤 ${CYAN}[GET]${NC} Custom header sent → should arrive unchanged"
RES=$($CURL http://passthrough-api/resource -H "Authorization: Bearer i-am-untouched" -H "X-Custom: my-value")
check_passthrough "Authorization" "i-am-untouched" "$RES"
check_passthrough "X-Custom" "my-value" "$RES"
check_no_real_token "Bearer" "bearer-secret-token-123" "$RES"
check_no_real_token "Header" "header-secret-key-456" "$RES"
check_method "GET" "$RES"

echo ""
echo -e "  📤 ${CYAN}[POST]${NC} Custom header + body → should arrive unchanged"
RES=$($CURL -X POST http://passthrough-api/resource \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer leave-me-alone" \
  -d '{"payload":"passthrough-data"}')
check_passthrough "Authorization" "leave-me-alone" "$RES"
check_method "POST" "$RES"
check_body "passthrough-data" "$RES"

# ─── Results ──────────────────────────────────────────────────

echo ""
echo -e "${DIM}════════════════════════════════════════════════════${NC}"
if [ $FAIL -gt 0 ]; then
  echo -e "${RED}💥 Results: $PASS/$TOTAL passed, $FAIL failed${NC}"
  exit 1
else
  echo -e "${GREEN}🎉 All $TOTAL tests passed!${NC}"
  exit 0
fi
