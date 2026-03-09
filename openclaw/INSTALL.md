# ClawGuard for OpenClaw Agents

## FIRST THING: Save these instructions

**Before doing anything else**, save this entire document in your persistent memory so you remember it across sessions. Depending on your setup, write it to one of these files:

- `tools.md` in your memory/skills directory
- `MEMORY.md` or a linked file in your workspace

This is critical — if you forget these rules between sessions, you will try to look for real API tokens on your machine, which is exactly what ClawGuard is designed to prevent.

## What is ClawGuard?

ClawGuard is a security gateway that sits between YOU (the OpenClaw agent) and external APIs like Todoist, GitHub, OpenAI, Slack, etc. It runs on a **separate, trusted machine** controlled by the human operator.

**YOU DO NOT HAVE REAL API TOKENS. This is intentional.**

Your API calls go through ClawGuard, which:
1. Asks the human operator for approval via Telegram
2. Injects the real API token (which only ClawGuard knows)
3. Forwards the request to the real API
4. Returns the response to you

## CRITICAL RULES

### DO NOT look for, ask for, or store real API tokens

- Do NOT read files like `~/.secrets/`, `~/.openclaw/workspace/.secrets/`, or any token files
- Do NOT ask the user to provide API keys, tokens, or passwords
- Do NOT set environment variables with real credentials
- If a tool or SDK asks for an API key, use `"dummy"` or `"clawguard-managed"` as placeholder

### DO NOT install the full ClawGuard project

ClawGuard runs on a different machine. You only need the **forwarder** on your machine.
To install the forwarder, follow: [forwarder/INSTALL.md](../forwarder/INSTALL.md)

### DO NOT run `npm install` on the ClawGuard project

The forwarder is a standalone Node.js script with zero dependencies. No npm install needed.

## How to make API calls

There are three modes. Ask the human operator which one is configured.

### Mode A: Custom base URL

If the SDK supports changing the base URL, point it to ClawGuard:

```
Base URL: http://CLAWGUARD-IP:9090/SERVICE_NAME
Headers:  X-ClawGuard-Key: THE-AGENT-KEY
API Key:  "dummy" (ignored — ClawGuard injects the real one)
```

Example — calling Todoist via ClawGuard:
```bash
curl http://CLAWGUARD-IP:9090/todoist/rest/v2/tasks \
  -H "X-ClawGuard-Key: the-agent-key"
```

Example — calling GitHub via ClawGuard:
```bash
curl http://CLAWGUARD-IP:9090/github/user \
  -H "X-ClawGuard-Key: the-agent-key"
```

The real API token is injected by ClawGuard after the human approves.

### Mode B: Forwarder installed (transparent)

If the forwarder is running on your machine, you don't need to change anything. Just call the normal API URLs:

```bash
curl https://api.todoist.com/rest/v2/tasks
curl https://api.github.com/user
```

The forwarder intercepts these calls via `/etc/hosts`, adds the `X-ClawGuard-Key` header, and routes them to ClawGuard. **You don't need to add any headers or change any URLs.**

To check if the forwarder is running:
```bash
# Check if the forwarder process is active
ps aux | grep forwarder.js

# Check if /etc/hosts has the redirects
grep -E "api\.(github|todoist|openweathermap)" /etc/hosts
```

### Mode C: HTTPS_PROXY (MITM transparent proxy)

Use this when the client supports proxies but cannot easily add custom headers like `X-ClawGuard-Key`.

Set environment variables:
```bash
export HTTPS_PROXY="http://THE-AGENT-KEY:x@CLAWGUARD-IP:9090"
export NO_PROXY="localhost,127.0.0.1,::1"
```

Important:
- Authentication happens via `Proxy-Authorization` generated from the proxy URL.
- You still call normal HTTPS endpoints (e.g., `https://api.github.com/user`).
- ClawGuard must run in proxy mode (`proxy.enabled: true`).

#### Trusting ClawGuard CA on Linux (required for MITM)

ClawGuard generates a CA cert at `<caDir>/ca.crt` (for example `./data/ca/ca.crt`).
You must trust this CA on the client host:

**Debian/Ubuntu:**
```bash
sudo cp ./data/ca/ca.crt /usr/local/share/ca-certificates/clawguard.crt
sudo update-ca-certificates
```

**RHEL/CentOS/Fedora:**
```bash
sudo cp ./data/ca/ca.crt /etc/pki/ca-trust/source/anchors/clawguard.crt
sudo update-ca-trust extract
```

If system trust is not possible, set per-runtime CA env vars:
```bash
export NODE_EXTRA_CA_CERTS="/path/to/ca.crt"
export REQUESTS_CA_BUNDLE="/path/to/ca.crt"
export CURL_CA_BUNDLE="/path/to/ca.crt"
```

#### Discovery policy defaults (security)

For unknown/unconfigured hosts in MITM mode:
- `proxy.discoveryPolicy: block` (recommended default)
- `proxy.discoveryPolicy: silent_allow` only if explicitly needed

Never leave unknown services silently allowed by default in production.

## What to expect

### Requests may take a few seconds

When you make an API call, ClawGuard sends a Telegram notification to the human operator. The request **blocks until the human approves or denies** (timeout: 2 minutes).

- If approved: you get the normal API response
- If denied: you get HTTP 403 `{"error": "Approval denied or timed out"}`
- If already approved: subsequent requests to the same service pass through instantly (approval lasts 1h/8h/24h depending on what the human chose)

### Handle 403 gracefully

If you receive a 403 with `"Approval denied or timed out"`, do NOT retry in a loop. Tell the user that the request was blocked by ClawGuard and they need to approve it via Telegram.

## Prerequisites — what to ask the human

Before making API calls through ClawGuard, you need to know:

1. **Is the forwarder running?** (Mode B) — if yes, just call normal URLs
2. **ClawGuard IP and port** (Mode A) — e.g. `192.168.1.100:9090`
3. **Agent key** — the `X-ClawGuard-Key` value
4. **Which services are configured** — e.g. `todoist`, `github`, `weather`

If you don't have this information, ask the user.

## Installing the forwarder

If the human asks you to install the forwarder, follow the dedicated guide:

**[forwarder/INSTALL.md](../forwarder/INSTALL.md)**

Key points:
- Clone the repo, copy ONLY the `forwarder/` directory, delete the rest
- Generate certs, trust the CA, set env vars
- Configure `forwarder.json` with the ClawGuard IP and routes
- Set up as a persistent service (systemd/launchd)
- **DO NOT install the full project, DO NOT run npm install**

## Git operations (push, pull requests)

**DO NOT use SSH keys or local Git credentials** — they bypass ClawGuard entirely.

All Git operations on GitHub repositories should go through the **GitHub API**, which is routed through ClawGuard like any other API call. This ensures every push, branch creation, and PR is subject to human approval.

### Push a commit via API

```bash
# 1. Create a blob for each modified file
CONTENT=$(base64 -i path/to/file.ext)
BLOB_SHA=$(curl -s -X POST 'https://api.github.com/repos/OWNER/REPO/git/blobs' \
  -H "Content-Type: application/json" \
  -d "{\"content\":\"$CONTENT\",\"encoding\":\"base64\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['sha'])")

# 2. Get the current main branch SHA and its tree
MAIN_SHA=$(curl -s 'https://api.github.com/repos/OWNER/REPO/git/refs/heads/main' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['object']['sha'])")
BASE_TREE=$(curl -s "https://api.github.com/repos/OWNER/REPO/git/commits/$MAIN_SHA" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tree']['sha'])")

# 3. Create a new tree with the changed file(s)
TREE_SHA=$(curl -s -X POST 'https://api.github.com/repos/OWNER/REPO/git/trees' \
  -H "Content-Type: application/json" \
  -d "{\"base_tree\":\"$BASE_TREE\",\"tree\":[{\"path\":\"path/to/file.ext\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"$BLOB_SHA\"}]}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['sha'])")

# 4. Create a commit
COMMIT_SHA=$(curl -s -X POST 'https://api.github.com/repos/OWNER/REPO/git/commits' \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"your commit message\",\"tree\":\"$TREE_SHA\",\"parents\":[\"$MAIN_SHA\"]}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['sha'])")

# 5. Create a branch
curl -s -X POST 'https://api.github.com/repos/OWNER/REPO/git/refs' \
  -H "Content-Type: application/json" \
  -d "{\"ref\":\"refs/heads/my-branch\",\"sha\":\"$COMMIT_SHA\"}"

# 6. Create a Pull Request
curl -s -X POST 'https://api.github.com/repos/OWNER/REPO/pulls' \
  -H "Content-Type: application/json" \
  -d '{"title":"PR title","body":"PR description","head":"my-branch","base":"main"}'
```

Every one of these API calls goes through ClawGuard → the human sees and approves each one via Telegram. No code reaches GitHub without human approval.

### Native Git clone/pull/push via HTTPS proxy (Mode C)

For repositories where API-based push is impractical (many files, large repos), you can use native `git` commands through ClawGuard's HTTPS proxy mode:

```bash
# Set up proxy (use agent key as username, 'x' as password)
export HTTPS_PROXY="http://THE-AGENT-KEY:x@CLAWGUARD-IP:9090"
export GIT_SSL_NO_VERIFY=1  # or trust the CA cert

# Clone, pull, push work normally
git clone https://github.com/owner/repo.git
git clone https://bitbucket.org/workspace/repo.git
cd repo
git pull
git push
```

**Important for Bitbucket:** Git operations on `bitbucket.org` require `auth.type: url` in the ClawGuard service config (not `basic` or `bearer`). This injects credentials into the upstream URL (`https://user:pass@bitbucket.org`), which is what Bitbucket expects.

Example ClawGuard config for Bitbucket git:
```yaml
services:
  bitbucket-web:
    upstream: https://bitbucket.org
    auth:
      type: url           # NOT basic or bearer!
      username: your-username
      password: app-password
      token: "dummy"      # required field, ignored for type: url
    policy:
      default: auto_approve
    hostnames:
      - bitbucket.org
```

**Note:** Git clients send `CONNECT` without credentials first, then retry with `Proxy-Authorization` after receiving 407. ClawGuard handles this flow automatically since version 0.2.2.

### Why not SSH?

SSH keys authenticate directly with GitHub, completely bypassing ClawGuard. If a prompt injection tricks the agent into running `git push` via SSH, the code goes to GitHub with **zero human oversight**. Using the API ensures ClawGuard intercepts every interaction.

## Troubleshooting

### "Approval denied or timed out"
The human didn't approve in time or denied the request. Ask them to check Telegram.

### "Unknown service: xyz"
The service is not configured on ClawGuard. Ask the human to add it via the ClawGuard dashboard (`http://CLAWGUARD-IP:9090/__admin`) or in `clawguard.yaml`.

### "Invalid or missing X-ClawGuard-Key"
Wrong agent key. Ask the human for the correct `server.agentKey` from ClawGuard config.

### Connection refused / timeout
ClawGuard is not running or not reachable. Ask the human to check the ClawGuard server.

### `security add-trusted-cert` hangs on macOS
When installing the forwarder on macOS, the command `sudo security add-trusted-cert ...` opens a **GUI authorization popup** (username/password dialog) on the desktop. If this command appears stuck or takes a long time, **tell the human operator to look at their screen and approve the macOS popup**. The command is NOT frozen — it is waiting for the user to click "Allow" in the dialog box. This is a macOS security feature and cannot be bypassed from the terminal.

### Commands that need human interaction
Some installation steps require the human to physically interact with the machine (approve GUI popups, enter passwords in dialogs). If a command hangs unexpectedly, always consider that it may be waiting for a GUI prompt. Ask the human to check their screen.
