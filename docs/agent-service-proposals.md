# Agent service proposals

An agent can propose a service; only the ClawGuard administrator can activate
it. Submission does not change live services or `security.allowedUpstreams`,
resolve secrets, initialize plugins, scan hosts, or call an upstream. This is
configuration validation, not a connectivity or credential test.

## Operator setup and review

Enable the dashboard with its existing PIN and IP allowlist. Set
`admin.strictMode: false` on the trusted ClawGuard machine to permit approvals.
Strict mode keeps YAML authoritative: proposals can still be reviewed and
rejected, but not activated. Disabling the dashboard disables agent proposals.

Open **Service proposals** in the dashboard:

1. Select **Review** and inspect the target, protocol, methods and approval policy.
   The requester and reason are agent-supplied context, not proof of identity.
2. Review private-target and TLS-verification exceptions, if present. SSH
   requires a complete pinned public host key; verify it independently before
   supplying it in the review form.
3. Fill each credential slot by pasting a value or choosing a compatible
   credential already managed by ClawGuard. Only credential labels and source
   paths are sent to the browser; reused values are copied on the server.
   Existing SSH private keys can be selected this way. A copied credential
   becomes part of the new service; later changes to its source do not rotate
   the copy automatically.
4. Explicitly allow any proposed domains that are outside the existing
   allowlist, then choose **Approve & add service**. This saves the service,
   allowlist additions and decision together. A failed initialization or save
   leaves the proposal pending. **Reject** makes that proposal terminal.

Decisions use the existing PIN/IP-protected admin surface, not Telegram request
approvals. The agent key grants neither approval nor credential-source access.
Ordinary API calls and SSH/FTP sessions retain their existing approval rules.
Protocol sidecars must already be enabled and deployed; a proposal cannot
enable a broker or change global server settings.

## Agent API

The endpoints are available on the ordinary gateway listener and the optional
admin HTTPS listener. Prefer HTTPS for remote access.

| Endpoint | Authentication | Purpose |
|---|---|---|
| `POST /__proposals/services` | `X-ClawGuard-Key` | Validate and enqueue a new service |
| `GET /__proposals/services/:id` | `X-ClawGuard-Key` | Read decision status, without credentials |

Send `X-ClawGuard-User` and `X-ClawGuard-Reason` to record provenance. The POST
body contains exactly `name` and `config`. `config` is the complete service
document used in YAML or the admin JSON editor, with these placeholders:

- `{"$clawguard":"credential"}` for an auth token, password, client ID/secret,
  injected JSON field, SSH private key, or plugin credential.
- `{"$clawguard":"input"}` at `ssh.knownHostKey` when the owner must supply a
  trusted public server identity. This is a public key, not a private key.

Do not send real credentials, secret-provider references, or the admin editor's
`keep-secret` markers. Public metadata such as a username, region or header
name can be supplied normally. Arbitrary plugin modules cannot be proposed:
only built-ins or an owner-configured plugin for the same protocol are accepted.
Extensible plugin configuration leaves are treated as credentials unless they
are recognized public metadata. Validation does not execute the plugin.

Successful submission returns HTTP **202**:

```json
{
  "id": "opaque-proposal-id",
  "name": "lombax",
  "status": "pending",
  "createdAt": "2026-09-30T12:00:00.000Z",
  "decidedAt": null,
  "activated": false,
  "validation": "configuration",
  "requirements": [{"path": "/auth/token", "kind": "credential"}],
  "requiredUpstreams": ["lombax.it"]
}
```

An identical resubmission while pending returns **200** and the same proposal
ID. A different pending proposal for the same alias, or an existing service,
returns **409**. Invalid documents return **400**. There can be at most 100
pending proposals, with a 64 KiB limit and bounded document nesting.

Status returns only ID, name, timestamps and `pending`, `approving`, `approved`
or `rejected`. Never interpret acceptance as activation. Do not retry a
rejected proposal automatically; ask the operator to review the intended
configuration. A replacement requires a new explicit submission.

## HTTP example: lombax.it with GET, POST and PUT

Save this credential-free request as `proposal.json`:

```json
{
  "name": "lombax",
  "config": {
    "protocol": "http",
    "upstream": "https://lombax.it",
    "hostnames": ["lombax.it"],
    "http": {"allowedMethods": ["GET", "POST", "PUT"]},
    "auth": {
      "type": "bearer",
      "token": {"$clawguard": "credential"}
    },
    "policy": {"default": "require_approval"}
  }
}
```

```bash
curl -k https://CLAWGUARD-HOST:9443/__proposals/services \
  -H 'Content-Type: application/json' \
  -H 'X-ClawGuard-Key: YOUR-AGENT-KEY' \
  -H 'X-ClawGuard-User: Fabio via agent' \
  -H 'X-ClawGuard-Reason: Add lombax.it for the requested integration' \
  --data-binary @proposal.json
```

`http.allowedMethods` is optional. When set, unlisted methods receive HTTP 405
before approval and credential injection, including through host routing and
HTTPS MITM. Omit it to retain the existing unrestricted-method behavior.
Supported values are GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. Policy
rules still determine which listed methods require a human request approval.

Other HTTP auth types use the same service schema:

| Auth type | Credential slots | Public configuration |
|---|---|---|
| `bearer`, `header`, `query` | `auth.token` | `headerName` / `paramName` as needed |
| `basic`, `url` | `auth.password` | `auth.username` or a credential slot |
| `oauth2_client_credentials` | `auth.clientId`, `auth.clientSecret` | `tokenPath` |
| `oauth2_authorization_code` | `auth.clientId`, optional `auth.clientSecret` | OAuth URLs, redirect URI, scopes, PKCE |
| `body_json` | Each `auth.fields` value | JSON field names |
| `plugin` | Plugin credential fields | Built-in name or trusted configured plugin |

OAuth authorization, when required by a provider, remains a separate operator
step. Placeholder validation cannot perform the provider's initial login.

## SSH example

```json
{
  "name": "lombax-ssh",
  "config": {
    "protocol": "ssh",
    "upstream": "ssh://server.lombax.it:22",
    "auth": {
      "type": "plugin",
      "pluginPath": "ssh-agent-key",
      "pluginConfig": {
        "username": "deploy",
        "privateKey": {"$clawguard": "credential"}
      }
    },
    "policy": {"default": "require_approval"},
    "ssh": {
      "allowPrivateTarget": false,
      "knownHostKey": {"$clawguard": "input"}
    }
  }
}
```

`knownHostKey` can instead contain an independently verified complete OpenSSH
public host key (`keytype base64`). Private targets require the explicit
`allowPrivateTarget: true` opt-in, reviewed by the operator. The private key
can be pasted or selected from existing managed credentials. SSH sessions
continue to require fresh approvals and host-key pinning.

## FTP/FTPS example

```json
{
  "name": "lombax-ftps",
  "config": {
    "protocol": "ftps",
    "upstream": "ftps://files.lombax.it:21",
    "auth": {
      "type": "plugin",
      "pluginPath": "ftp-password",
      "pluginConfig": {
        "username": "deploy",
        "password": {"$clawguard": "credential"}
      }
    },
    "policy": {"default": "require_approval"},
    "ftp": {
      "allowPrivateTarget": false,
      "tlsMode": "explicit",
      "root": "/incoming"
    }
  }
}
```

For plain FTP, set `protocol: ftp`, use `ftp://host:21`, and remove `tlsMode`.
SFTP, SCP and SSH forwarding are unsupported. The approved service does not
create an FTP lease or bypass the existing read-only/read/write decision.

## Persistence

SQLite stores immutable credential-free proposal documents and their
decisions in `service_proposals`. Approval saves the service in
`services_override` and new allowlist entries in `admin_upstreams` within one
transaction. On restart ClawGuard restores approved domains before validating
service overrides. Strict mode ignores both overrides and approved domains.
An interrupted `approving` state is reset to pending on startup.

Deleting a service through the existing editor does not revoke approved
domain entries. Forwarder routes, local DNS/hosts entries and client trust
configuration remain agent-installation tasks after approval; this API
provisions the trusted gateway configuration only.
