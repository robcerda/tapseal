# Threat model

## Setting

An AI agent runs on a machine operated by a third party: a hosted agent
platform, a cloud VM, a managed sandbox. The agent needs some of your
credentials. You don't control the machine, its snapshots, its backups,
its logs, or the people who administer it.

## Goal and ceiling

**Goal:** long-lived secrets are never decryptable from anything the host
stores. A secret reaches the host only because you tapped a key for it, and
it expires on its own.

**Ceiling:** whatever the agent actually uses, the host can read while it
is live. tapseal bounds how long that exposure lasts and how much is
exposed. It does not prevent it.

## Adversaries

### Host operator, or anyone with root, snapshots, backups, or logs

| They get | Outcome |
|---|---|
| Vault blobs | Useless. The host never holds a key that opens them |
| Identity key | Can sign new requests, so you must still check the name before each tap. Cannot open past deliveries |
| Chat history and agent logs with every `tsd1` ever pasted | Useless. Request keys are deleted on use or expiry |
| Root during a live window | Whatever is live: a 1h Google access token, or a `file` secret |

A `file` secret (a session cookie, an API token) stays valid until the
provider expires it. Deleting the file does not revoke it. Shorter delivery
windows reduce how often it is exposed, not how long a stolen copy lasts.

Memory snapshots of a running VM include tmpfs. Treat "live" as "readable by
the operator."

### Phishing via the agent

A compromised host can send links to a lookalike domain.
- WebAuthn binds credentials to the RP ID, so a lookalike gets no PRF output.
- The unlock flow never asks for the paper key. Paper recovery lives only at
  `#recover`, which you navigate to yourself. **A page reached from a chat
  link that asks for your paper key is an attack.**
- Delivery is encrypted to a request signed by the identity key you pinned,
  so a link cannot redirect a delivery to another machine.

### The agent itself

Gating controls *access to* secrets, not *use of* them. A prompt-injected
agent can request an unlock for a plausible reason, or use a live token
directly instead of through its intended tool.
- The page shows the verified secret name before you deliver. Read it.
- Give the agent the rules in [AGENT.md](AGENT.md): no unlock requests driven
  by content it reads, no direct use of raw tokens.
- For real enforcement, put a credential proxy in front of providers so the
  host never holds a usable token. Out of scope for v1.

### Your unlock page and its hosting

The page is a trust anchor. Anyone who can change what it serves can ship a
version that captures `K` on your next tap.
- Protect the repo and hosting accounts with your security keys.
- Never give the agent access to either.
- **Use a dedicated subdomain.** WebAuthn credentials are scoped to the RP ID
  (the hostname). On `<user>.github.io`, every Pages site on your account
  shares that origin, and any of them could exercise your credentials.
- The CSP limits network egress to Google's token endpoint. That stops
  accidental leaks, not a malicious redeploy.

## Not addressed

- A compromised phone or browser.
- Coercion, or theft of a key together with its PIN.
- The paper key: it alone opens everything. Store it offline.
- Touch fatigue: you tapping through an unlock you didn't expect.

## Tiers

Unattended jobs cannot wait for a tap. Decide per secret:

- **Gated:** sealed, unlocked per use, live for a window you choose.
- **Resident:** stored in plaintext on the host because it must be used
  unattended. Treat it as already exposed. Scope it as narrowly as the
  provider allows, and rotate it when you adopt tapseal. Encryption doesn't
  help here; don't pretend it does.

Rule of thumb: if a secret is needed unattended, it's resident, and your
effort goes into shrinking its scope. Otherwise it's gated, and its delivery
window is how long you're willing to have it exposed.
