# tapseal

Let an AI agent on someone else's server use your secrets, without that
server being able to read them.

Your secrets stay locked under your YubiKey. When the agent needs one, it
sends you a link. You tap your key on your phone, and the agent gets that one
secret for as long as you choose. Then it is deleted.

Anyone who steals the server's disk, backups, or logs gets nothing they can open.

## Setup (once)

1. **Host the unlock page.** Push this repo to GitHub and serve the `site`
   folder on a subdomain you own, like `unlock.yourdomain.com`. GitHub Pages
   and Cloudflare Pages both work.
2. **Test your keys.** On your phone, open
   `https://unlock.yourdomain.com/#selftest`. You want PASS for each key.
3. **Install on the agent.** Give the agent [docs/AGENT.md](docs/AGENT.md)
   and have it run:
   ```sh
   git clone https://github.com/<you>/tapseal
   cd tapseal
   pip install --user .
   tapseal init
   ```
   It also sets `TAPSEAL_URL` to your page and schedules `tapseal sweep`
   every minute. It sends you back a public key and a fingerprint.
4. **Enroll.** On your phone, open `#enroll`. Register your YubiKeys, paste
   the agent's public key, write down the paper key, and commit the
   `config.js` it gives you to your repo. Check that the fingerprint on the
   page's home screen matches the agent's.

## Add a secret

1. On your phone, open `#seal`.
2. Name it, paste the secret, and tap your key.
3. Send the `tsv1…` text it gives you to the agent. The agent stores it but
   cannot open it.
4. Tell the agent which tool uses it.

Use a fresh secret. Anything the server has ever seen unencrypted should be
treated as exposed.

## Use a secret

1. The agent sends you a link and says what it needs.
2. Tap the link, then your YubiKey.
3. Check the name, choose how long it stays available, and tap **Deliver**.
4. Paste the `tsd1…` text back to the agent.

When the time is up, the secret is deleted from the server.

## Lost your keys?

Type `https://unlock.yourdomain.com/#recover` into the browser yourself and
enter your paper key. Never enter it on a page you reached from a link.

## Good to know

**Limits.** While a secret is in use, someone with root on the server can
read it. An agent can also misuse a secret you gave it. Details in
[docs/THREATS.md](docs/THREATS.md).

**Secrets needed around the clock**, for example by a scheduled job, can't
wait for a tap. Those stay unencrypted on the server, so give them the
smallest permissions possible.

**Requirements.** A YubiKey 5 or Bio (or any FIDO2 key with PRF) with a PIN
set. Chrome on Android, or Safari on iOS 18 and later. On the server, Linux
and Python 3.10 or newer.

**More.** [Full setup](docs/SETUP.md), [formats](docs/SPEC.md),
[reporting security issues](SECURITY.md). Tests live in `tests`.

## License

MIT
