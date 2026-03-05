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

There are two modes. Ask the human operator which one is configured.

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
