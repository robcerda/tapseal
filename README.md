# tapseal

Hardware-key-gated secrets for AI agents running on hosts you don't control.

Your agent lives on someone else's server. It needs your API tokens and
sessions, but anyone with root on that server, or its snapshots, can read
whatever is on disk. tapseal keeps your secrets sealed under a key that only
your security key (YubiKey or any FIDO2 key with PRF) can open. When the agent
needs one, it sends you a link; you tap your key on your phone, and the agent
gets that one secret for a window you choose.

```
 Phone (trusted while open)            Chat                 Agent host (untrusted)
┌─────────────────────────────┐                     ┌─────────────────────────────┐
│ unlock page (static, yours) │◄── unlock link ─────│ tapseal                     │
│  WebAuthn PRF ◄─► YubiKey   │                     │  vault/*.tsv  (ciphertext)  │
│  open blob, verify request  │── paste "tsd1…" ───►│  one-shot request keys      │
│  encrypt to request key     │                     │  live secrets in tmpfs,     │
└─────────────────────────────┘                     │  deleted at expiry          │
                                                    └─────────────────────────────┘
```

**What it protects against:** someone who gets the agent host's disk,
snapshots, backups, or logs. They find only ciphertext they cannot open,
including every delivery you ever pasted into chat.

**What it does not:** someone with root *while* a secret is live can read
that secret. A misbehaving or prompt-injected agent can misuse a secret you
unlocked. Read [the threat model](docs/THREAT-MODEL.md) before relying on this.

## How it works

1. **Seal** (once per secret, on your phone): paste the secret into your
   unlock page, tap your key, send the resulting `tsv1…` blob to the agent.
   The agent stores it and cannot open it.
2. **Unlock** (when needed): the agent creates a one-shot request, signed by
   its identity key, and sends you a link. Your page checks the signature
   against the identity you pinned at enrollment, you tap your key, check the
   name, pick how long it stays live, and paste the `tsd1…` string back.
3. **Expire:** the agent writes the secret to tmpfs and deletes it at expiry.
   It deleted the request key on receipt, so the pasted string can never be
   opened again.

There's no server-side component of your own and no account. The unlock page
is a static site you host. The VM side is a Python CLI plus an MCP server.

## Quick start

Full walkthrough: [docs/SETUP.md](docs/SETUP.md).

**1. Host your unlock page.** Use this repo as a template, then serve
`site/` from a domain you control: GitHub Pages (workflow included) or
Cloudflare Pages. Use a dedicated subdomain; see the setup guide for why.

**2. Install on the agent host.**

```sh
pipx install "tapseal[mcp] @ git+https://github.com/<you>/tapseal"
tapseal init                      # prints the identity key; fingerprint on stderr
```

Add the MCP server to your agent:

```json
{
  "mcpServers": {
    "tapseal": {
      "command": "tapseal-mcp",
      "env": { "TAPSEAL_URL": "https://unlock.example.com/" }
    }
  }
}
```

and give it [docs/AGENT.md](docs/AGENT.md) as standing instructions.

**3. Enroll on your phone.** Open `https://unlock.example.com/#selftest`,
then `#enroll`. Register your keys, paste the identity key, write down the
paper key, and commit the generated `config.js`.

**4. Seal a secret, point its tool at `/dev/shm/tapseal/<name>`, and ask
the agent to do something that needs it.**

## Requirements

- A FIDO2 security key with the `hmac-secret` extension (all current
  YubiKey 5 and Bio models), with a PIN or fingerprint set.
- A phone browser with WebAuthn PRF: Chrome on Android, Safari on iOS 18+.
  The page's `#selftest` tells you if your combination works.
- On the agent host: Python 3.10+, Linux with `/dev/shm` (tmpfs).

## Layout

```
site/        the unlock page: static, no build step, no dependencies
tapseal/     VM side: core, CLI (`tapseal`), MCP server (`tapseal-mcp`)
docs/        SETUP, THREAT-MODEL, SPEC, AGENT
tests/       Node <-> Python interop; full browser flow with a virtual authenticator
```

## Tests

```sh
python3 -m unittest tests/test_interop.py    # needs node and `cryptography`
python3 tests/browser_e2e.py                 # needs `playwright` (PW_CHANNEL=chrome to use installed Chrome)
```

## Status

Pre-1.0. The formats are versioned (`tsv1`, `tsr1`, `tsd1`) and specified in
[docs/SPEC.md](docs/SPEC.md). Not independently audited. Report security issues
per [SECURITY.md](SECURITY.md).

## License

MIT
