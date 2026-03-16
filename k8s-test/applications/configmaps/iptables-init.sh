#!/bin/sh
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

echo ""
echo -e "${BOLD}🔀 ClawGuard iptables init${NC}"
echo -e "${DIM}──────────────────────────${NC}"

echo -e "  🔧 Redirecting port ${CYAN}80${NC}  → ${CYAN}8080${NC}  (HTTP)"
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --uid-owner 1000 -j REDIRECT --to-ports 8080

echo -e "  🔧 Redirecting port ${CYAN}443${NC} → ${CYAN}8443${NC}  (HTTPS)"
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner 1000 -j REDIRECT --to-ports 8443

echo ""
echo -e "  ${GREEN}✅ iptables rules applied:${NC}"
echo -e "${DIM}"
iptables -t nat -L OUTPUT -n -v
echo -e "${NC}"

echo ""
echo -e "  ${GREEN}✅ iptables-save:${NC}"
echo -e "${DIM}"
iptables-save
echo -e "${NC}"
