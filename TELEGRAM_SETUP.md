# Telegram Setup Guide

Step-by-step instructions to set up Telegram notifications and approval flow for ClawGuard.

## 1. Create a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Choose a display name (e.g. `ClawGuard Security`)
4. Choose a username (e.g. `clawguard_yourname_bot`) — must end with `bot`
5. BotFather will reply with your **bot token**. It looks like: `7123456789:AAH0_some-random-string-here`
6. **Save this token** — you'll need it in the config

Optional but recommended:
- Send `/setdescription` to BotFather and set: `Security gateway for OpenClaw agents. Approve or deny agent requests.`
- Send `/setuserpic` to add an icon

## 2. Get Your Chat ID

You need your personal chat ID so ClawGuard knows where to send notifications.

1. Open Telegram and search for **@userinfobot**
2. Send `/start`
3. It will reply with your user info including your **chat ID** (a number like `123456789`)
4. **Save this number** — you'll need it in the config

Alternative method:
1. Send any message to your new bot
2. Open this URL in your browser (replace YOUR_BOT_TOKEN):
   ```
   https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
   ```
3. Look for `"chat": {"id": 123456789}` in the response

## 3. Configure ClawGuard

Edit `clawguard.yaml`:

```yaml
notifications:
  telegram:
    botToken: "${TELEGRAM_BOT_TOKEN}"    # or paste the token directly
    chatId: "123456789"                     # your chat ID from step 2
    pairing:
      enabled: true
      secret: "my-secret-pairing-code"   # choose a random string
```

Set the environment variable:

```bash
export TELEGRAM_BOT_TOKEN="7123456789:AAH0_some-random-string-here"
```

## 4. Start ClawGuard

```bash
npm run build
TELEGRAM_BOT_TOKEN=your-token npm start
```

You should see:

```
📱 Telegram notifier started — ⚠️  NOT PAIRED
   Send /pair my-secret-pairing-code to the bot from your Telegram account
```

## 5. Pair Your Account

This step is **critical for security**. Until the configured chat is paired, ClawGuard denies every request that needs approval.

1. Open the **configured chat** in Telegram — the 1:1 chat (or group) whose id you set in `chatId`.
2. Send: `/pair my-secret-pairing-code` (use the secret you set in the config)
3. The bot replies: `✅ Paired successfully!`
4. ClawGuard logs: `✅ Telegram paired with user: YourName`

From now on, only your paired chat can approve or deny requests.

> **Pairing only works from the configured `chatId`.** `/pair`, `/unpair`, `/status` and `/showlog` sent from any other chat are silently ignored (logged as `🚫 Ignoring … from non-configured chat <id>`). This prevents a stranger who finds your bot from brute-forcing the secret, leaking metadata via `/showlog`, or disabling approvals with `/unpair`. Repeated wrong `/pair` attempts from the configured chat are also rate-limited.
>
> **Tip — finding a group's chat id:** add the bot to the group and send `/pair <secret>` there once; even though it's ignored (the group isn't configured yet), ClawGuard logs the group id in the `🚫 Ignoring…` line. Put that id in `chatId`, restart, then `/pair` again in the group to complete pairing. (Or use a helper bot like `@getidsbot`.)

## 6. Test It

From another terminal:

```bash
curl http://localhost:9090/openai/v1/models \
  -H "X-ClawGuard-Key: your-agent-key"
```

You should receive a Telegram message like:

```
🛡️ ClawGuard — Approval Request

🔹 Service: openai
🔹 Method: GET
🔹 Path: /v1/models
🔹 Agent IP: ::1
🔹 Time: 28/2/2026, 15:30:00

[✅ Only this request] [🎯 Choose scope] [❌ Deny]
[⚡ Quick once] [⚡ 1h method-wide]
```

Tap **Only this request** to approve one request. To reuse an approval, tap
**Choose scope**, review its scope, then tap a duration.

The second row provides quick approvals. **Quick once** approves only the
pending request, like **Only this request**. **1h method-wide** approves the
request's HTTP method on all paths and queries of that service for one hour.
It does not approve other methods or other services. These shortcuts do not
replace the scope editor. Requests that require a fresh decision do not offer
the method-wide shortcut.

### HTTP approval scopes

The scope editor updates the same Telegram message. It starts with the exact
path, all query parameters and the request's HTTP method. No access is granted
while you change the scope.

1. Tap **Path** to select a complete path or an ancestor from the list.
2. Tap **Query** to select how query parameters must match.
3. Tap **Methods** to select additional HTTP methods, if needed.
4. Tap a duration to approve the scope shown in the summary.

Path choices show the actual prefix at each depth. Long lists have **Next** and
**Previous** buttons. Selecting an ancestor includes its subpaths so the scope
still covers the pending request. For the complete path, **Subpaths** switches
between that path alone and that path with its descendants. `/repo` with
subpaths matches `/repo` and `/repo/info`, but not `/repo-other`.

| Query option | Matching rule |
|---|---|
| **Same parameters and values** | All names and values must match. Extra or missing parameters do not match. |
| **Ignore query** | Query parameters do not restrict the scope. |
| **Choose parameters** | Only the selected names must have the same values. Other parameters can change. |

Query names and values are case-sensitive and use URL form decoding. Changing
the order of different parameter names does not change the scope. Repeated
parameters must retain their values, count and order for that name. Sensitive
parameter values are hidden in the scope preview. The selected values still
participate in matching.

The original method stays selected. Additional methods come from the service's
method allowlist, or the standard HTTP methods when no allowlist is configured.
Choose **15m**, **30m**, **1h**, **4h**, **24h**, **1w**, **1month** or **Forever**
in the summary to apply the grant. **1w** means seven days; **1month** means
30 days. **Forever** has no expiry. You can still revoke it, and a service
configuration change still invalidates it. The dashboard labels it **Until
revoked** instead of showing an expiry date.
The grant always belongs to one service. Existing service restrictions still
apply. Requests that require a fresh decision, including protected plugin
operations, SSH sessions and FTP leases, do not gain reusable HTTP scopes.

**Only this request** creates no reusable approval. **Deny** rejects the pending
request. Editing does not extend its approval timeout. Menu buttons are bound
to the message and the approver who opened the editor. Old buttons, double
taps and expired requests cannot create or extend a grant. If a URL cannot
be safely matched, or is too long for the editor, **Choose scope** is not
offered. The quick buttons remain available for ordinary HTTP requests.

Scopes retain their expiry after a restart. A service configuration change
invalidates its scopes when next used. The dashboard's **Approvals** page shows
the path, subpath setting, query rule, methods and expiry. **Revoke** removes
that scope; **Revoke service** and `/revoke <service>` remove all approvals for
the service. `/allow` replaces existing scopes for that service.

Existing method-wide and exact-path approvals keep their original meaning
after an upgrade. They remain visible and revocable in the dashboard.

## Telegram Bot Commands

| Command | What it does |
|---|---|
| `/help` | Lists commands, arguments and examples |
| `/pair <secret>` | Links your Telegram to ClawGuard (required before approving) |
| `/unpair` | Removes pairing and revokes temporary service approvals |
| `/status` | Shows pairing, enhanced alerts, showlog and temporary approvals with time remaining |
| `/alerts [on\|off\|status]` | Shows or changes Home Assistant/webhook alerts; Telegram approvals stay active |
| `/showlog [on\|off]` | Shows or changes info-only logs for automatic calls |
| `/allow` | Opens buttons to choose a service and duration |
| `/allow <service>` | Opens approval buttons for the named service |
| `/allow <service> <duration>` | Temporarily approves HTTP requests or SSH sessions for one service |
| `/allow <service> <duration> read_only\|read_write` | Temporarily approves FTP/FTPS leases with the selected access mode |
| `/revoke` | Opens buttons for services with an active temporary approval |
| `/revoke <service>` | Revokes temporary and cached approvals for that service |

ClawGuard registers these commands in the Telegram bot menu at startup. All
commands apply only in the configured chat. `/allow`, `/revoke` and `/alerts` also require
a paired chat and an account permitted by `allowedApprovers`, when configured.
Bot accounts and anonymous group senders cannot create or revoke grants or change alerts.

### Home Assistant and webhook alerts

Send `/alerts off` to stop new enhanced alerts without changing Telegram
approval requests, service policies or logs. This cancels queued escalation
timers as well. The setting is global for the configured outbound webhook and
persists in SQLite across restarts. `/alerts on` enables alerts for new requests;
it does not replay requests queued or received while alerts were off. `/alerts`
and `/alerts status` show the current setting.

An alert already sent cannot be recalled. If `cancelOnResolve: true`, ClawGuard
still sends its matching `approval_resolved` event when the request finishes,
so Home Assistant can clear it. Muted requests generate neither event.

The webhook must already be configured with `notifications.webhook.enabled: true`.
The command cannot enable a webhook disabled in YAML. To disable the channel
through configuration instead, set the existing flag and restart ClawGuard:

```yaml
notifications:
  webhook:
    enabled: false
```

Keep the existing Telegram configuration and other webhook fields. Changing
`escalateAfterSeconds` to `0` sends alerts immediately; it does not disable them.

### Temporary service approvals

To permit work while you cannot answer approval requests:

1. Send `/allow` in the configured chat.
2. Tap the service name. Use **Next** or **Previous** for more services.
3. For FTP/FTPS, tap **Read only** or **Read/write**.
4. Tap a duration: **15m**, **30m**, **1h**, **4h**, **8h** or **24h**.
5. Tap **Revoke now** in the confirmation to end the grant early.

The duration button activates the approval. The message shows the service,
target and access mode before that choice. **Services** goes back to the list;
**Cancel** closes the menu without granting access. You can also send
`/allow lombax-coolify-1` to open that service directly, or use the complete
command `/allow lombax-coolify-1 1h`. `/status` shows the remaining time.

Selection menus expire after ten minutes and can be used only by the account
that opened the menu. The confirmation's revoke button lasts until the grant
expires. Each click replaces the previous buttons. A changed or
deleted service requires a new review. Double taps cannot duplicate or extend
a grant. A stale **Revoke now** button cannot revoke a newer grant. After a
ClawGuard restart, send `/revoke` to get fresh buttons for active grants.

To revoke a grant from the service list:

1. Send `/revoke`.
2. Tap the service to revoke its temporary and cached approvals.

The list includes only services with an active `/allow`. Use **Next** or
**Previous** to change pages. **Cancel** closes the list without a change.
If a grant expires or is renewed after the list opens, its old button cannot
revoke it. Send `/revoke` again to get the current list. The command
`/revoke <service>` also works for a service with cached HTTP approvals only.

Use a duration from `1m` to `24h`, such as `30m`, `1h` or `8h`. A grant covers
all new requests for that service, including operations that normally require
a fresh decision. It does not bypass method allowlists, blocked operations,
target checks, host-key checks or credential isolation. Pending prompts retain
their original decision and timeout; the grant applies to subsequent requests.

Creating or renewing a grant replaces earlier cached HTTP approvals for the
same service, including approvals for an exact path. For example, `/allow app
30m` replaces an earlier GET approval for one hour. That GET approval cannot
resume after the 30 minutes. Approvals for other services remain valid.

Creating or renewing a grant enables `/showlog`. While showlog is on, calls
under the grant send silent, info-only log messages with no approval buttons.
`/showlog off` stops these logs and other automatic-call logs. This setting
persists across restarts. `/showlog on` enables logs again. A new `/allow` also
enables logs again. This setting does not stop approval requests or the audit
log. A message already sent to Telegram can still arrive after the setting
changes. Telegram suppresses sound for temporary-grant logs; notification
display depends on the Telegram app settings.

Grants persist across restarts with their original expiry. A service
configuration change invalidates its grant when it is next used. Expiry,
revocation or unpairing stops use of the grant for new requests. Existing SSH
sessions and FTP leases keep their normal lifetime. After expiry, requests
follow the configured service policy and any new HTTP approvals explicitly
granted after `/allow`. An `auto_approve` policy still allows requests; `/allow`
does not change that policy.

## Troubleshooting

### "The bot doesn't respond"
- Make sure `TELEGRAM_BOT_TOKEN` is correct
- Make sure the bot is running (check ClawGuard logs for `📱 Telegram notifier started`)
- Telegram bot polling requires outbound internet access on port 443

### "I don't receive approval notifications"
- Check that your `chatId` in the config matches your actual Telegram chat ID
- Make sure you've paired: send `/status` to the bot
- If pairing is enabled, you MUST pair before receiving notifications

### "Callback buttons don't work"
- The bot must be running when you tap the button
- If ClawGuard was restarted, pending requests from before the restart are lost — send a new request
- Buttons expire after the approval timeout (default: 120 seconds)

### Repeated `409 Conflict: terminated by other getUpdates request`

Telegram permits only one active long-polling consumer for a bot. Current
ClawGuard pauses after a repeated conflict instead of fighting another poller
forever. In that fail-closed state, pending approvals are denied, new approval
requests fail immediately, and the admin health panel shows `409 guard: paused`.

Check for an old container, replica or deployment using the same bot, without
printing its environment or token:

```bash
docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' | grep -i clawguard
docker compose ps --all
```

Also check any previous host, Coolify application, Swarm/Kubernetes replica,
systemd service or PM2 process. Stop the duplicate, then restart the intended
ClawGuard instance. One bot cannot be shared by two long-polling ClawGuard
replicas; use a distinct Telegram bot per independently running deployment.

Run exactly one polling consumer per bot. During a deployment, stop the old
instance before starting the replacement; an overlapping rolling deployment can
trip the guard and intentionally pause the new instance. Once paused, removing
the duplicate is not enough: restart the intended ClawGuard instance afterward.

For monitoring, alert when `telegram.pollingCircuitOpen` is true **or** when
`telegram.polling` is false in `GET /__status`. A successful outbound
`sendMessage` does not prove that ClawGuard is receiving button callbacks; only
the polling health does. ClawGuard deliberately does not issue a separate raw
`getUpdates` request as a health check or lock-reclaim operation, because that
would itself compete with the real long poll.

Do not attach an automatic container-restart healthcheck to this conflict state.
The ClawGuard process intentionally remains alive (and `restart: unless-stopped`
therefore does not restart it); repeatedly restarting while the duplicate still
exists would only create deployment thrashing.

### "Someone else can talk to my bot"
Telegram bots are publicly reachable — anyone can DM your bot or add it to their own group. That's fine: ClawGuard only sends approval requests to the configured `chatId`, and only acts on `/pair`/`/unpair`/`/showlog` from that same chat. Messages from any other chat are received but ignored. To keep the secret strong:
```yaml
pairing:
  enabled: true
  secret: "a-strong-random-secret"   # openssl rand -hex 32
```

### "I want multiple people to approve" (group mode)
- Set `chatId` to a **group/supergroup id** and pair the group — every member of that group can then approve. The first tap wins.
- **Keep the group private**: anyone in it can approve. To restrict approvals to specific people even inside a shared group, use `allowedApprovers`:
  ```yaml
  allowedApprovers:
    - "@alice"
    - "123456789"   # numeric Telegram user id
  ```
- Optional `messageThreadId` posts approvals into a specific forum topic of the group.
