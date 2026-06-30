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

[✅ Approve 1h] [✅ Approve 8h] [❌ Deny]
```

Tap **Approve 1h** and the request goes through!

## Telegram Bot Commands

| Command | What it does |
|---|---|
| `/pair <secret>` | Links your Telegram to ClawGuard (required before approving) |
| `/unpair` | Removes the link (you stop receiving requests) |
| `/status` | Check if you're currently paired |

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
