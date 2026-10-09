# Threat model

## Setting

An AI agent runs on a machine operated by a third party: a hosted agent
platform, a cloud VM, a managed sandbox. The agent needs some of your
credentials. You don't control the machine, its snapshots, its backups, its
logs, or the people who administer it.

## Goal and ceiling

**Goal:** nothing the host stores, at any time, can decrypt your secrets,
forge your approval, or sign on your behalf. A secret reaches the host only
because you tapped a key for it, and it expires on its own.

**Ceiling:** whatever the agent actually uses, the host can read while it is
live. tapseal bounds how long that exposure lasts and how much is exposed. It
does not prevent it.

## Adversaries

### Someone with the host's disk, snapshots, backups, or logs

| They get | Outcome |
|---|---|
| Vault blobs | Useless: no key on the host opens them |
| Pinned page public key | Public by design |
| Chat history and agent logs with every link and `tsd1` ever pasted | Useless. Request keys lived only in RAM and were deleted |
| The VM identity key | Not on disk. It lives in RAM and is regenerated after every reboot |

A disk thief who wants a secret has to get you to certify an identity they
control (a `#certify` link) and then tap an unlock. Both arrive through your
chat with the agent. **Certify only when your agent just restarted and asked
in your usual chat.**

### Root on the live host

| They get | Outcome |
|---|---|
| Live secrets | Readable during their window: a 1 hour Google token, or a `file` secret |
| The identity key in RAM | Can request unlocks while its certificate is valid. You still tap for each, and the page shows the verified name |
| Memory snapshots | Include tmpfs. Treat "live" as "readable by the operator" |

A `file` secret (a session cookie, an API token) stays valid until the
provider expires it. Deleting the file does not revoke it. Shorter windows
reduce how often it is exposed, not how long a stolen copy lasts.

### Someone who sees an unlock link

They can encrypt to the request key, but cannot sign as your page. The VM
refuses unsigned deliveries before using up the request, so your real
delivery still works.

### Phishing via the agent

A compromised host can send links to a lookalike domain.

- **Lookalikes get nothing from your key.** WebAuthn binds credentials to the
  RP ID, so a lookalike gets no PRF output.
- **The unlock flow never asks for the paper key.** Paper recovery lives only
  at `#recover`.
- **Never reach `#seal`, `#enroll`, `#rotate` or `#recover` from a link.**
  A lookalike `#seal` captures what you paste, and needs no key to do it. Use
  bookmarks.
- **Set an anti phishing phrase** on the home page. It is stored only on your
  device and shown on every view. If it is missing, close the page.
- **Deliveries can't be redirected.** They go to a request signed by an
  identity you certified.

### The agent itself

Gating controls *access to* secrets, not *use of* them. A prompt injected
agent can request an unlock for a plausible reason, or use a live token
directly instead of through its intended tool.

- The page shows the verified secret name before you deliver. Read it.
- Give the agent the rules in [AGENT.md](AGENT.md).
- For real enforcement, a credential proxy would keep usable tokens off the
  host entirely. Out of scope for v1.

### Your unlock page and its hosting

The page is the trust anchor. Anyone who can change the JavaScript your device
loads can capture `K` on your next tap. GitHub Pages and HTTPS are not the weak
points. These are:

1. **The origin.**
   - Use a dedicated custom subdomain, never `<user>.github.io`. Every Pages
     site on the account shares that origin, and any of them could use your
     keys. The page refuses to enroll on `*.github.io`.
   - The page also refuses to run on any hostname other than its configured RP ID.
2. **Who can push.** Anything that can push to the branch Pages deploys from
   can ship a malicious page.
   - GitHub: security key 2FA only.
   - No broad `repo` scope tokens on everyday machines or in agent sessions.
   - Push this repo with a touch required SSH key (`sk-ed25519`).
   - Turn on deploy notifications.
   - Never give the agent access.
3. **DNS.**
   - Verify your domain in GitHub's Pages settings before adding the CNAME,
     so a dangling record cannot be claimed.
   - If the zone is on Cloudflare, make the record DNS only: proxying
     terminates TLS and adds a party that can rewrite the page.
   - Security key 2FA on the DNS provider. Registrar lock and auto renew.
   - Never delete the Pages site while DNS still points at it.
4. **Typed URLs.** Neither `github.io` nor most domains send HSTS. On hostile
   Wi-Fi, an address typed without `https://` can be intercepted. Bookmark the
   full `https://` addresses. Consider HSTS preload for your domain.
5. **Your device.** No MDM profile and no custom root certificates on the
   device you unlock with. A trusted rogue root defeats HTTPS completely.

**Headers.** GitHub Pages ignores `site/_headers`. So COOP, `no-store` and
header based framing protection apply only on Cloudflare Pages. The page
compensates where it can: a meta CSP, and refusing to run inside a frame.

**Persistence.** A single malicious deploy could register a service worker
that keeps serving bad code after you fix the repo. tapseal never registers
one. After any suspected compromise, clear the site's data in your browser.

## Revocation

Removing a key or getting a new paper key only works through `#rotate` (or
`#recover`, which always rotates). That makes a new vault key and page key and
re-seals your blobs.

Simply re-wrapping the old vault key would revoke nothing: old `config.js`
files remain in git history.

Old blobs in the host's backups still open with the old vault key. If a lost
key's PIN or the old paper key may be in someone else's hands, re-issue the
underlying secrets too.

## Not addressed

- A compromised device or browser.
- Coercion, or theft of a key together with its PIN.
- The paper key: it alone opens everything. Store it offline.
- Touch fatigue: tapping through an unlock you didn't expect.

## Tiers

Unattended jobs cannot wait for a tap. Decide per secret:

- **Gated:** sealed, unlocked per use, live for a window you choose.
- **Resident:** stored in plaintext on the host because it must be used
  unattended. Treat it as already exposed. Scope it as narrowly as the
  provider allows, and rotate it when you adopt tapseal.

**Rule of thumb:**
- If a secret is needed unattended, it is resident, and your effort goes into
  shrinking its scope.
- Otherwise it is gated, and its delivery window is how long you're willing to
  have it exposed.
