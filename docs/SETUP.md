# Setup

About 30 minutes. Everything except step 2 can be done from a phone.

## 0. Before you start

- **Security keys.** Two is strongly recommended. Set a FIDO2 PIN on each
  (YubiKey Bio: enroll a fingerprint too). Keys without NFC connect to the
  phone over USB-C.
- **A subdomain you control**, e.g. `unlock.example.com`. Credentials are
  bound to it. Moving later means re-enrolling with the paper key; sealed
  blobs survive the move.
  - Don't use a bare `<user>.github.io`: every Pages site on your account
    shares that origin. See [THREAT-MODEL.md](THREAT-MODEL.md).
- **Your chat app must open links in the real browser** (Safari or Chrome),
  not an in-app webview. WebAuthn generally fails in webviews. Use "Open in
  browser" if needed.

## 1. Host the unlock page

Create your own copy: **Use this template** on GitHub, or clone and push.
Then pick one host.

**GitHub Pages**
1. Settings → Pages → Source: **GitHub Actions**.
2. Settings → Secrets and variables → Actions → Variables: add
   `TAPSEAL_PAGES` = `true`. `.github/workflows/pages.yml` then deploys
   `site/` on every push that touches it.
3. Settings → Pages → Custom domain: your subdomain. Enforce HTTPS.

GitHub Pages can't set response headers. The page carries its CSP in a meta
tag and refuses to run inside a frame, which covers what matters.

**Cloudflare Pages**
1. Create a Pages project from your repo: build command empty, output
   directory `site`.
2. Add your subdomain as a custom domain. `site/_headers` sets CSP,
   `frame-ancestors`, and `no-store`.

**Either way:** protect the repo and hosting accounts with your security keys,
and never give the agent access to them.

Open `https://unlock.example.com/#selftest` and get **PASS** for every
phone + key combination you'll use, each from a fresh page load.

## 2. Install on the agent host

The agent does this step. Give it [AGENT.md](AGENT.md) as standing
instructions, then have it run:

```sh
git clone https://github.com/<you>/tapseal && cd tapseal
pip install --user .                                  # only dependency: cryptography
export TAPSEAL_URL="https://unlock.example.com/"      # persist in the agent's env
tapseal init
( crontab -l 2>/dev/null; echo '* * * * * tapseal sweep' ) | crontab -
```

`init` prints the identity public key on stdout and its fingerprint on stderr.
The agent posts both to you in chat.

The sweep deletes expired secrets and request keys. Without cron, run
`tapseal sweep --loop 30` under whatever supervisor the host has.

**Not Linux?** Set `TAPSEAL_SHM` to a RAM-backed directory. On disk, live
secrets would survive in backups.

## 3. Enroll

1. Open `#enroll` and tap **Start**.
2. Register each key by label (two touches each).
3. Paste the identity key and tap **Generate config.js**.
4. Write the **paper key** on paper, check it, tick the box, and generate
   again.
5. Replace `site/config.js` in your repo with the output and commit (GitHub
   mobile web works). The site redeploys.
6. Open the home page. It must list your keys and show a VM key fingerprint
   **identical** to the one `tapseal init` printed. If they differ, stop.

## 4. Seal your first secret

Pick something low-stakes.

1. **Re-issue** the credential (a new token or session). Don't reuse
   anything the host ever held in plaintext.
2. Open `#seal`. Enter the name (e.g. `oura`), the kind, and the longest
   delivery window you'll allow. Paste the secret, tap **Seal**, and send
   the `tsv1…` string to the agent.
3. Point the tool that needs it at `/dev/shm/tapseal/<name>`, e.g.:
   ```sh
   ln -sfn /dev/shm/tapseal/oura ~/.oura/session.json
   ```
4. Ask the agent to do something that needs it. Tap the link, then your key.
   Check the **verified** name, pick a window, tap **Deliver**, and paste the
   `tsd1…` string back.
5. Let it expire. The tool should fail cleanly and the agent should ask
   again. If the tool crash-loops instead, fix that before migrating more.

## 5. Recovery drill

On a different phone, open `#recover` by typing the address yourself,
enter the paper key, and confirm it unlocks key management. Don't save
anything.

## Google kind

Delivers a 1-hour access token minted on your phone. The refresh token never
reaches the host.

1. Get a refresh token without a laptop. Use the OAuth Playground with your
   own OAuth client: gear icon → "Use your own OAuth credentials". Add
   `https://developers.google.com/oauthplayground` as a redirect URI on the client.
2. Seal `{"client_id","client_secret","refresh_token","scopes"}` as kind
   `google`, choosing the token format your tool reads.
3. Publish the OAuth app to **In production**. Refresh tokens from apps in
   "Testing" expire after 7 days.

If Google rejects the token mint from the browser, the page says so and
delivers nothing.
