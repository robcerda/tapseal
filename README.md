# tapseal

Approval gated secrets for AI agents running on servers you don't control.

Your agent's secrets stay sealed under your YubiKey. When the agent needs one,
it sends you a link; you tap your key, and the agent gets that one secret for a
window you choose.

## What it gives you

1. **Secrets the agent isn't using stay locked.** Nothing the server stores can
   open them: not its disk, its backups, or the chat and agent logs. A breach
   of any of those, now or later, gets ciphertext.
2. **You approve every window of use.** The agent cannot start using a locked
   secret without your tap, and the page shows you exactly which secret it is.
3. **Real time limits where the provider allows it.** For Google, your device
   mints a one hour token and the refresh token never leaves it. A copy dies
   with the token.

## What it does not give you

1. **The server can read a secret while it is unlocked.** The computer using a
   secret has to see it. That includes whoever runs the server, and memory
   snapshots of it.
2. **Deletion at the end of the window is done by the server's own software.**
   An honest server deletes it. A compromised one can keep a copy, and nothing
   on your side can prove otherwise. A copied static API key or session cookie
   works until you revoke it. Only credentials that expire at the provider
   have a time limit the server cannot get around.
3. **No protection from whoever controls your chat with the agent.** They can
   pretend to be you to the agent, and the agent to you. If the agent's
   provider also runs the chat, that is the same party.
4. **No protection from an agent misusing a secret you gave it.**

## Is it for you?

**Good fit:**
1. Secrets the agent needs now and then, not constantly.
2. High value accounts: financial, admin, anything that can reset other
   accounts.
3. Providers that issue short lived tokens.

**Poor fit:** secrets used constantly or by unattended jobs. They can't wait
for a tap. Keep those on the server in plain form, scoped as narrowly as the
provider allows, and rotate them.

For any secret, your best tripwire is the provider's own logs. Use you did not
unlock means a copy exists somewhere: rotate it.

Details in [docs/THREATS.md](docs/THREATS.md).

## Setup (once)

1. **Host the unlock page.** Create your own deploy repo from this template
   (private if you can) and serve its `site` folder on a subdomain you own,
   like `unlock.yourdomain.com`. Never deploy from a repo that accepts outside
   contributions. Not on `yourname.github.io`: the page refuses to enroll
   there. Details in [docs/SETUP.md](docs/SETUP.md).
2. **Test your keys.** On your device, open
   `https://unlock.yourdomain.com/#selftest`. You want PASS for each key.
3. **Enroll.** Open `#enroll`, register your YubiKeys, write down the paper
   key, and commit the `config.json` it gives you to your deploy repo. Then set
   an anti phishing phrase on the home page.
4. **Install on the agent.** Give the agent [docs/AGENT.md](docs/AGENT.md)
   and have it run:
   ```sh
   git clone https://github.com/<you>/tapseal ~/tapseal
   cd ~/tapseal && git checkout <latest release>
   python3 -m venv ~/.local/tapseal-venv && ~/.local/tapseal-venv/bin/pip install .
   ~/.local/tapseal-venv/bin/tapseal init
   ```
   It also sets `TAPSEAL_URL` to your page and schedules `tapseal sweep`
   every minute.
5. **Certify the agent.** It sends you a certify link. Open it only if the
   agent just started or restarted and asked in your usual chat, pick how long
   it lasts, and tap your key. Paste the result back. After every reboot of the
   agent's server it asks again.

## Add a secret

1. On your device, open `#seal` from your bookmark. Never from a link.
2. Name it, paste the secret, and tap your key.
3. Send the `tsv1…` text it gives you to the agent. The agent stores it but
   cannot open it.
4. Tell the agent which tool uses it, and to point the tool straight at the
   file tapseal writes, not through a symlink.

Use a fresh secret. Anything the server has ever seen unencrypted should be
treated as exposed.

**Check the tool once.** Seal a made up value under the same name, let the tool
use it, let it expire, then have the agent search its disk, logs, and
transcript for that value. Finding it means the tool keeps copies. The value is
fake, so searching for it is safe.

## Use a secret

1. The agent sends you a link and says what it needs.
2. Tap the link, then your key.
3. Check the name and the sealed date, choose how long it stays available,
   and tap **Deliver**.
4. Paste the `tsd1…` text back to the agent.

When the window ends, the server's tapseal deletes it.

## Updates

Your deploy repo checks this repo for new releases daily and opens a pull
request with the changes. Read it, then merge. Nothing reaches your page until
you do.

## Lost a key?

Open `#rotate` from your bookmark. If you lost every key, open `#recover`
instead and enter your paper key. Never enter it on a page you reached from a
link. Both make a new vault key, so lost keys and the old paper key stop
working. Certified something you shouldn't have? `#revoke` cancels every
certificate with one commit.

## Good to know

**Requirements.** A YubiKey 5 or Bio (or any FIDO2 key with PRF) with a PIN
set. Chrome on Android, or Safari on iOS 18 and later. On the server: Linux, a
persistent shell and home directory, a tmpfs such as `/dev/shm`, cron or a
process supervisor, and Python 3.10 or newer. Many hosted agents reset their
sandbox between sessions; those cannot run tapseal.

**Status.** Not independently audited. The formats are versioned and specified
in [docs/SPEC.md](docs/SPEC.md).

**More.** [Full setup](docs/SETUP.md), [threat model](docs/THREATS.md),
[reporting security issues](SECURITY.md). Tests live in `tests`.

## License

MIT
