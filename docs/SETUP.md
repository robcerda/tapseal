# Setup

About 30 minutes, all from a device except what the agent does.

## 0. Before you start

**Security keys.**
- Two is strongly recommended.
- Set a FIDO2 PIN on each. On a YubiKey Bio, also enroll a fingerprint.
- Keys without NFC connect to the device over USB-C.

**A custom subdomain you control**, e.g. `unlock.example.com`.
- Credentials are bound to it. Moving later means recovering with the paper
  key on the new domain; sealed blobs survive.
- **Not `<user>.github.io`.** The page refuses to enroll there. See
  [THREATS.md](THREATS.md).

**Accounts.**
- Security key 2FA on GitHub and your DNS provider.
- Keep repo-wide `gh` or PAT tokens off machines and agents that don't need them.

**Your chat app must open links in the real browser** (Safari or Chrome), not
an in-app webview. WebAuthn generally fails in webviews.

## 1. Host the unlock page

**Deploy from your own repo, never from one that accepts outside
contributions.** Whatever deploys to your unlock page can capture your vault
key, so a merged pull request on a shared repo would be a merged pull request
on your vault. Keep this repo (upstream) and your deployment separate, and
bring in updates only by reviewing them.

**Create your deploy repo.**
1. On this repo, **Use this template** → **Create a new repository**. Make it
   **private** if your plan allows Pages on private repos (the page itself is
   public either way; private keeps your config history to yourself). The
   deploy repo only needs `site/`, `.github/workflows/pages.yml` and
   `update.yml`, and `.tapseal-version`; you can delete everything else.
2. In the new repo, Settings → Secrets and variables → Actions → Variables:
   - `TAPSEAL_PAGES` = `true` (deploys `site/` on every push that touches it)
   - `TAPSEAL_UPSTREAM` = `robcerda/tapseal` (proposes updates, see below)
3. Settings → Actions → General → Workflow permissions: allow GitHub Actions to
   **create pull requests**.
4. Settings → Rules → Rulesets: protect `main` against force pushes and
   deletion.

**GitHub Pages.**
1. Settings → Pages → Source: **GitHub Actions**. Run the `pages` workflow once
   from the Actions tab.
2. Account Settings → Pages → **Verified domains**: verify your domain.
3. At your DNS provider, add a `CNAME` from your subdomain to
   `<user>.github.io`.
   - **DNS only** (on Cloudflare: grey cloud).
   - No wildcards.
4. Repo Settings → Pages → Custom domain: your subdomain. Enforce HTTPS.

**Cloudflare Pages** works too: no build command, output directory `site`.
There `site/_headers` applies (CSP, COOP, framing, `no-store`).

**Bookmarks.** Bookmark `https://unlock.example.com/` and
`https://unlock.example.com/#recover` on your device, with the full `https://`.

Open `https://unlock.example.com/#selftest`. Get **PASS** for every device and
key combination you'll use, each from a fresh page load.

## 2. Enroll (device only)

1. Open `#enroll` and tap **Start**.
2. Register each key by label (two touches each). Keys are registered as
   discoverable, so on a hardware key each one uses a resident slot. That is
   what lets `config.json` omit credential IDs. The type defaults to
   **Hardware security key**. **Synced passkey** (iCloud Keychain, 1Password) is
   available for convenience, but any one slot opens the whole vault; read
   [THREATS.md](THREATS.md) first.
3. Tap **Generate config.json**. Write the **paper key** on paper, check it,
   tick the box, and generate again.
4. Replace `site/config.json` in your repo with the output and commit (GitHub
   mobile web works). The site redeploys.
5. On the home page, set an **anti phishing phrase**. It lives only on this
   device and appears on every view.

## 3. Install on the agent

**The agent needs:**
- a Linux host with a persistent shell and home directory (blobs and the
  pinned page key live there);
- a tmpfs such as `/dev/shm`;
- cron or a process supervisor;
- Python 3.10 or newer with pip.

Hosted agents that reset their sandbox between sessions cannot run tapseal.
Neither can macOS today, since it has no `/dev/shm`.

Give the agent [AGENT.md](AGENT.md) as standing instructions, then have it run:

```sh
git clone https://github.com/<you>/tapseal && cd tapseal
pip install --user .                                  # only dependency: cryptography
export TAPSEAL_URL="https://unlock.example.com/"      # persist in the agent's env
tapseal init                                          # prints a certify link
( crontab -l 2>/dev/null; echo '* * * * * tapseal sweep' ) | crontab -
```

The sweep deletes expired secrets, request keys, and certificates. Without
cron, run `tapseal sweep --loop 30` under whatever supervisor the host has.

`TAPSEAL_SHM` must be tmpfs (default `/dev/shm/tapseal`). tapseal refuses to
run if it is not, because keys would reach disk.

## 4. Certify the agent

The agent sends you a certify link.
1. Open the link. Ask yourself: did the agent just start or restart, and did
   it ask in your usual chat, at a time you expect? The page cannot check this
   for you. The fingerprint it shows comes from the link itself.
2. Pick how long the certificate lasts (default 7 days), and tap your key.
3. Paste the `tsc1…` string back. The agent runs `tapseal certify`, which also
   pins your page key the first time.

The identity lives in RAM. After every host reboot the agent runs
`tapseal init` and asks you to certify again. On every unlock, the page says
whether the certificate came from this device.

**Certified something you should not have?** Open `#revoke` from your bookmark,
commit the `config.json` it gives you, and every older certificate stops working.

## 5. Seal your first secret

Pick something low-stakes.

1. **Re-issue** the credential: a new token or session. Don't reuse anything
   the host ever held in plaintext.
2. Open `#seal` **from your bookmark**.
   1. Enter the name (e.g. `oura`), the kind, and the longest delivery window
      you'll allow.
   2. Paste the secret and tap **Seal**.
   3. Send the `tsv1…` string to the agent.
   4. Clear your clipboard.
3. Point the tool that needs it at `/dev/shm/tapseal/<name>` directly,
   through an environment variable or config option.
   - Avoid symlinking the tool's own config path to tmpfs. Tools that rewrite
     their config replace the link with a plaintext file on disk that never
     expires.
   - Check the tool does not cache tokens or log them.
4. Ask the agent to do something that needs it.
   1. Tap the link, then your key.
   2. Check the **verified** name and the sealed date.
   3. Pick a window (it defaults to the shortest) and tap **Deliver**.
   4. Paste the `tsd1…` string back.
5. Let it expire. The tool should fail cleanly and the agent should ask again.
   If the tool crash-loops instead, fix that before migrating more.

## 6. Rotation and recovery

**Lost a key, or worried about the paper key?** Open `#rotate` from your
bookmark, unlock with a key you still have, then:
1. Register every key you still have.
2. Ask the agent for `tapseal export` and paste the `tsb1…` bundle. Blobs that
   do not open under your old vault key are skipped and named.
3. Write down the new paper key.
4. Commit the new `config.json`.
5. Send the agent the **rotation package** (`tsk1…`). It runs `tapseal rotate`,
   which accepts it only because your old page key signed it, then sends you
   a certify link.

**Lost all keys?** Same flow, from `#recover` with the paper key.

**Drill.** On a different device, open `#recover` from a bookmark and confirm the
paper key is accepted. Stop there, without generating anything.

## Updates

Your deploy repo runs `.github/workflows/update.yml` daily.
**What it does:**
- When upstream publishes a newer release tag that is on upstream `main`, it
  copies upstream's `site/` into a branch off your `main` and opens a pull
  request.
- Your `config.json` is never touched.
- A closed update is never proposed again.

**What it refuses:**
- an upstream `site/` containing any file outside the expected set;
- a subdirectory or symlink;
- minified looking code.

Any file served from your origin can use your keys. Your Pages workflow runs
the same file check before every deploy.

**Nothing changes until you merge.**
- Read the diff first: this is the one moment upstream code can reach your
  vault key.
- The PR calls out changes to page code and headers (`core.js`, `app.js`,
  `index.html`, `_headers`).
- It lists each file's sha256 and links the exact upstream commit.
- Merging deploys the update.
- Workflow files are never synced. The PR says when yours differ from
  upstream's.

Optional: set the variable `TAPSEAL_ALLOWED_SIGNERS` to an SSH
`allowed_signers` line, e.g. `maintainer@example.com ssh-ed25519 AAAA...`. Then
only release tags signed by that key are proposed, so a stolen upstream token
cannot get a release in front of you.

The agent side updates the same way: `git pull` and `pip install --user .` at
a release tag you have reviewed.

## Upgrading a deploy repo from 0.2 to 0.3

0.3 replaces `site/config.js` with `site/config.json` and stops publishing key
labels and credential IDs. The update workflow refuses the new file set until
you do this once:
1. Copy `.github/workflows/update.yml` and `pages.yml` from the latest upstream release
   into your deploy repo.
2. Rename `site/config.js` to `site/config.json`, and turn its contents into
   plain JSON: drop `window.TAPSEAL_CONFIG = ` and the final `;`.
3. Copy upstream's `site/` from that release over yours, keeping your
   `config.json`, and commit.
4. Open `#enroll` from your bookmark. It says **Upgrade keyring**. Unlock, then
   register every key and passkey again. Commit the `config.json` it gives you.

Your vault key, page key, paper key, and sealed secrets are unchanged. Agents
need nothing.

## Google kind

Delivers a 1 hour access token minted on your device. The refresh token never
reaches the host.

1. Get a refresh token without a laptop: the OAuth Playground with your own
   OAuth client (gear icon → "Use your own OAuth credentials"). Add
   `https://developers.google.com/oauthplayground` as a redirect URI.
2. Seal `{"client_id","client_secret","refresh_token","scopes"}` as kind
   `google`, choosing the token format your tool reads.
3. Publish the OAuth app to **In production**. Refresh tokens from apps in
   "Testing" expire after 7 days.

If Google rejects the token mint from the browser, the page says so and
delivers nothing.
