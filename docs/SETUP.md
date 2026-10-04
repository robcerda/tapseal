# Setup

About 30 minutes, all from a phone except what the agent does.

## 0. Before you start

**Security keys.**
- Two is strongly recommended.
- Set a FIDO2 PIN on each. On a YubiKey Bio, also enroll a fingerprint.
- Keys without NFC connect to the phone over USB-C.

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

**Your own copy.** **Use this template** on GitHub, or fork.

**GitHub Pages.**
1. Settings → Pages → Source: **GitHub Actions**.
2. Settings → Secrets and variables → Actions → Variables: add `TAPSEAL_PAGES`
   = `true`. `.github/workflows/pages.yml` deploys `site/` on every push that
   touches it. You can also run it once from the Actions tab.
3. Account Settings → Pages → **Verified domains**: verify your domain.
4. At your DNS provider, add a `CNAME` from your subdomain to
   `<user>.github.io`.
   - **DNS only** (on Cloudflare: grey cloud).
   - No wildcards.
5. Repo Settings → Pages → Custom domain: your subdomain. Enforce HTTPS.

**Cloudflare Pages** works too: no build command, output directory `site`.
There `site/_headers` applies (CSP, COOP, framing, `no-store`).

**Bookmarks.** Bookmark `https://unlock.example.com/` and
`https://unlock.example.com/#recover` on your phone, with the full `https://`.

Open `https://unlock.example.com/#selftest`. Get **PASS** for every phone and
key combination you'll use, each from a fresh page load.

## 2. Enroll (phone only)

1. Open `#enroll` and tap **Start**.
2. Register each key by label (two touches each).
3. Tap **Generate config.js**. Write the **paper key** on paper, check it,
   tick the box, and generate again.
4. Replace `site/config.js` in your repo with the output and commit (GitHub
   mobile web works). The site redeploys.
5. On the home page, set an **anti phishing phrase**. It lives only on this
   phone and appears on every view.

## 3. Install on the agent

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

The agent sends you the certify link and a fingerprint.
1. Open the link.
2. Check that the fingerprint matches.
3. Pick how long the certificate lasts, and tap your key.
4. Paste the `tsc1…` string back. The agent runs `tapseal certify`, which also
   pins your page key the first time.

The identity lives in RAM. After every host reboot the agent runs
`tapseal init` and asks you to certify again. Certify only when you expect it.

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
3. Point the tool that needs it at `/dev/shm/tapseal/<name>`, e.g.:
   ```sh
   ln -sfn /dev/shm/tapseal/oura ~/.oura/session.json
   ```
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
2. Paste the bundle from `tapseal export`.
3. Write down the new paper key.
4. Commit the new `config.js`.
5. Send the re-sealed bundle to the agent with: `tapseal import`,
   `tapseal repin`, `tapseal init --force`, then send the certify link.

**Lost all keys?** Same flow, from `#recover` with the paper key.

**Drill.** On a different phone, open `#recover` from a bookmark and confirm the
paper key is accepted. Stop there, without generating anything.

## Google kind

Delivers a 1 hour access token minted on your phone. The refresh token never
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
