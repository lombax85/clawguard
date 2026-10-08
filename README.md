# ClawGuard

**A security proxy for autonomous agents.**

ClawGuard lets an AI agent call external APIs without holding your real API keys or tokens. Credentials stay on a separate trusted machine; ClawGuard checks each request against your rules and asks for approval on Telegram when needed.

## How it works

1. The agent sends a request using placeholder credentials.
2. ClawGuard applies your rules: allow, block, or ask for your approval.
3. If allowed, it adds the real credentials, forwards the request, and records it in the audit log.

For example, you can allow reads automatically and require approval before the agent changes or deletes data.

Use it with API calls made by **OpenClaw**, **OpenAI Codex**, **Claude Code**, or other autonomous AI agents. Route those calls through ClawGuard using a custom API URL, a local forwarder, or an HTTPS proxy.

## Get started

Run ClawGuard on a trusted machine whose files the agent cannot read, configure your services, and pair Telegram. Then connect the agent to the proxy.

- [Setup and configuration](docs/GUIDE.md#quick-start)
- [Telegram setup](TELEGRAM_SETUP.md)
- [Local forwarder](forwarder/INSTALL.md) · [OpenClaw setup](openclaw/INSTALL.md)
- [SSH gateway](ssh-gateway/README.md) · [FTP/FTPS gateway](ftp-gateway/README.md)

**Experimental:** not yet independently audited for production credentials.

MIT · By [Fabio Lombardo](https://github.com/lombax85)
