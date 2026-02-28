# ClawGuard Forwarder — Installation Guide for OpenClaw Agents

**READ THIS FIRST:** You only need the `forwarder/` directory. Do NOT install the full ClawGuard project — that runs on a separate, secure machine. You are installing ONLY the lightweight forwarder on the agent's machine.

## What is this?

The forwarder is a tiny HTTPS interceptor that runs on YOUR machine (the agent machine). It has:
- **Zero dependencies** — just Node.js, nothing to `npm install`
- **No real API tokens** — it only knows how to reach the ClawGuard server
- **One job** — intercept HTTPS calls to specific domains and forward them to ClawGuard

## Prerequisites

You need from the human operator:
1. **ClawGuard server IP and port** (e.g. `192.168.1.100:9090`)
2. **Agent key** (the `server.agentKey` value from ClawGuard config)
3. **Which domains to intercept** (e.g. `api.github.com`, `api.openweathermap.org`)

If you don't have these, ask the user before proceeding.

## Step-by-step installation

### Step 1: Get the forwarder files only

```bash
# Clone the repo to a temp location
git clone https://github.com/lombax85/clawguard.git /tmp/clawguard-repo

# Copy ONLY the forwarder directory to its final location
cp -r /tmp/clawguard-repo/forwarder ~/clawguard-forwarder
cd ~/clawguard-forwarder

# Clean up the full repo — you don't need it
rm -rf /tmp/clawguard-repo
```

### Step 2: Generate certificates for the domains to intercept

Replace the domain list with the actual domains you need:

```bash
chmod +x generate-certs.sh
./generate-certs.sh api.github.com
```

For multiple domains:
```bash
./generate-certs.sh api.github.com api.openweathermap.org
```

### Step 3: Trust the local CA

The forwarder creates a local Certificate Authority. You must trust it so HTTPS works.

**IMPORTANT:** You must do BOTH sub-steps below — adding the CA to the OS trust store alone is NOT enough for most tools (curl, Python, Node.js often use their own certificate bundles).

#### Step 3a: Add CA to OS trust store

**Linux:**
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/clawguard-ca.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
```

#### Step 3b: Set environment variables for your runtime

Many tools (Homebrew curl, Python, Node.js) do NOT read the OS Keychain/trust store. You must tell them where to find the CA cert explicitly.

Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, or equivalent):

```bash
# For Node.js (OpenClaw, npm packages, etc.)
export NODE_EXTRA_CA_CERTS=~/clawguard-forwarder/certs/ca.crt

# For Python (requests, httpx, etc.)
export REQUESTS_CA_BUNDLE=~/clawguard-forwarder/certs/ca.crt
export SSL_CERT_FILE=~/clawguard-forwarder/certs/ca.crt

# For curl (if installed via Homebrew on macOS)
export CURL_CA_BUNDLE=~/clawguard-forwarder/certs/ca.crt
```

Then reload your shell:
```bash
source ~/.zshrc   # or ~/.bashrc
```

**Quick test** — after setting these, verify the cert is trusted:
```bash
curl -s https://api.github.com 2>&1 | head -5
# If you see JSON, the cert is trusted.
# If you see "SSL certificate problem", the env vars are not set correctly.
```

### Step 4: Configure the forwarder

```bash
cp forwarder.json.example forwarder.json
```

Edit `forwarder.json`:

```json
{
  "clawguard": "http://192.168.1.100:9090",
  "agentKey": "the-agent-key-from-clawguard-config",
  "listenHost": "127.0.0.1",
  "listenPort": 443,
  "certsDir": "./certs",
  "routes": {
    "api.github.com": "github",
    "api.openweathermap.org": "weather"
  }
}
```

**Important fields:**
- `clawguard` — the IP:port of the ClawGuard server (NOT localhost, it's on another machine)
- `agentKey` — must match `server.agentKey` in ClawGuard's `clawguard.yaml`
- `routes` — maps each intercepted domain to the service name configured in ClawGuard

### Step 5: Add /etc/hosts entries

Redirect the target domains to localhost so the forwarder can intercept them:

```bash
echo "127.0.0.1 api.github.com api.openweathermap.org" | sudo tee -a /etc/hosts
```

### Step 6: Start the forwarder

```bash
sudo node forwarder.js
```

Needs `sudo` because it listens on port 443 (privileged port).

You should see:
```
╔══════════════════════════════════════════════╗
║   🔀 ClawGuard Forwarder                    ║
║   Runs on agent machine — no real tokens     ║
╚══════════════════════════════════════════════╝

🔗 ClawGuard:  http://192.168.1.100:9090
🖥️  Listening:  https://127.0.0.1:443
📡 Routes:
   api.github.com → http://192.168.1.100:9090/github
   api.openweathermap.org → http://192.168.1.100:9090/weather
```

## How it works after setup

```
Your code calls https://api.github.com/repos/user/repo
       ↓
/etc/hosts resolves api.github.com to 127.0.0.1
       ↓
Forwarder (port 443) receives the HTTPS request
       ↓
Forwarder adds X-ClawGuard-Key header
       ↓
Forwarder forwards to http://192.168.1.100:9090/github/repos/user/repo
       ↓
ClawGuard asks for Telegram approval → injects real token → calls real API
       ↓
Response flows back through the chain
```

**Example: a prompt injection tries to delete a GitHub repo.**
The agent (compromised by a malicious prompt) calls `DELETE https://api.github.com/repos/mycompany/production-api`. The forwarder sends this to ClawGuard. ClawGuard sends you a Telegram notification:

```
🛡️ ClawGuard — Approval Request
🔹 Service: github
🔹 Method: DELETE
🔹 Path: /repos/mycompany/production-api
```

You see `DELETE` + `/repos/` and tap **Deny**. The request is blocked. Your repo is safe.

## Step 7: Run as a persistent service (recommended)

Running `sudo node forwarder.js` in a terminal will stop when the terminal is closed. To keep the forwarder running permanently, set it up as a system service.

### Linux (systemd)

Create the service file:

```bash
sudo tee /etc/systemd/system/clawguard-forwarder.service > /dev/null <<'EOF'
[Unit]
Description=ClawGuard Forwarder
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /home/YOUR_USER/clawguard-forwarder/forwarder.js
WorkingDirectory=/home/YOUR_USER/clawguard-forwarder
Restart=always
RestartSec=5
Environment=NODE_EXTRA_CA_CERTS=/home/YOUR_USER/clawguard-forwarder/certs/ca.crt

[Install]
WantedBy=multi-user.target
EOF
```

Replace `YOUR_USER` with your actual username, then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable clawguard-forwarder
sudo systemctl start clawguard-forwarder
```

Check status:
```bash
sudo systemctl status clawguard-forwarder
sudo journalctl -u clawguard-forwarder -f   # follow logs
```

### macOS (launchd)

Create the plist file:

```bash
sudo tee /Library/LaunchDaemons/com.clawguard.forwarder.plist > /dev/null <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.clawguard.forwarder</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/node</string>
        <string>/Users/YOUR_USER/clawguard-forwarder/forwarder.js</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Users/YOUR_USER/clawguard-forwarder</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/clawguard-forwarder.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/clawguard-forwarder.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>NODE_EXTRA_CA_CERTS</key>
        <string>/Users/YOUR_USER/clawguard-forwarder/certs/ca.crt</string>
    </dict>
</dict>
</plist>
EOF
```

Replace `YOUR_USER` with your actual username. Check the path to `node` with `which node` and update if different (e.g. `/opt/homebrew/bin/node`).

```bash
sudo launchctl load /Library/LaunchDaemons/com.clawguard.forwarder.plist
```

Check status:
```bash
sudo launchctl list | grep clawguard
tail -f /tmp/clawguard-forwarder.log   # follow logs
```

To stop:
```bash
sudo launchctl unload /Library/LaunchDaemons/com.clawguard.forwarder.plist
```

---

## Uninstall

```bash
# 1. Stop the service
# Linux:
sudo systemctl stop clawguard-forwarder
sudo systemctl disable clawguard-forwarder
sudo rm /etc/systemd/system/clawguard-forwarder.service
sudo systemctl daemon-reload
# macOS:
sudo launchctl unload /Library/LaunchDaemons/com.clawguard.forwarder.plist
sudo rm /Library/LaunchDaemons/com.clawguard.forwarder.plist

# 2. Remove /etc/hosts entries (edit manually to remove only the lines you added)
sudo nano /etc/hosts
# Delete the line(s) containing api.github.com, api.openweathermap.org, etc.

# 3. Remove the forwarder
rm -rf ~/clawguard-forwarder

# 4. Untrust the CA
# Linux:
sudo rm /usr/local/share/ca-certificates/clawguard-ca.crt
sudo update-ca-certificates
# macOS:
# Open Keychain Access → System → find "ClawGuard Local CA" → delete

# 5. Remove env vars from your shell profile (~/.zshrc or ~/.bashrc)
# Delete the NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE, SSL_CERT_FILE, CURL_CA_BUNDLE lines
```

## Troubleshooting

### "EACCES: permission denied, listen 443"
Run with `sudo`: `sudo node forwarder.js`

### "ClawGuard unreachable"
- Check that ClawGuard is running on the remote machine
- Verify the IP and port in `forwarder.json`
- Test connectivity: `curl http://192.168.1.100:9090/__status`

### "SSL certificate problem" or "certificate verify failed"
This is the most common issue. The CA cert is not trusted by the tool making the request.

1. **Check Step 3b** — make sure you set the env vars (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, etc.)
2. **Verify they're set:** `echo $NODE_EXTRA_CA_CERTS` should print the cert path
3. **Verify the cert file exists:** `ls -la ~/clawguard-forwarder/certs/ca.crt`
4. **For Node.js specifically:** `export NODE_EXTRA_CA_CERTS=~/clawguard-forwarder/certs/ca.crt`
5. **For Python specifically:** `export REQUESTS_CA_BUNDLE=~/clawguard-forwarder/certs/ca.crt`
6. **For Homebrew curl on macOS:** `export CURL_CA_BUNDLE=~/clawguard-forwarder/certs/ca.crt`
7. **As a last resort** (testing only): `export NODE_TLS_REJECT_UNAUTHORIZED=0`

Note: the macOS system `curl` (`/usr/bin/curl`) uses the Keychain and should work with Step 3a alone. But Homebrew curl (`/opt/homebrew/bin/curl`) uses OpenSSL and needs the env var.

### "Unknown service: xyz" from ClawGuard
The forwarder reached ClawGuard, but ClawGuard doesn't have a service named "xyz" configured.

- **If using the web dashboard:** the service must be added there. But note: the upstream domain (e.g. `api.github.com`) must be listed in `security.allowedUpstreams` in `clawguard.yaml`. If it's not, the dashboard will reject the addition with an error.
- **If using YAML config:** add the service to `services:` section AND its domain to `security.allowedUpstreams`.
- The service name in `forwarder.json` routes must match exactly (e.g. `"api.github.com": "github"` means ClawGuard must have a service named `github`).

### "Unknown host" from the forwarder
- The domain is not in `routes` in `forwarder.json`
- Add it and restart the forwarder
