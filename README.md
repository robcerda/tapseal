# tapseal

Let an AI agent on someone else's server use your secrets, while keeping
everything it is not using right now locked away from that server.

Your secrets stay sealed under your YubiKey. When the agent needs one, it
sends you a link. You tap your key on your device, and the agent gets that one
secret for as long as you choose. Then the server deletes it.

Nothing the server stores can open a sealed secret: not its disk, its backups,
or the chat and agent logs. What it can do is read a secret while you have it
unlocked, and a long lived token copied then stays valid after it is deleted.
So prefer short lived credentials, and read the limits below.

## Setup (once)

1. **Host the unlock page.** Create your own deploy repo from this template
   (private if you can) and serve its `site` folder on a subdomain you own,
   like `unlock.yourdomain.com`. Never deploy from a repo that accepts outside
   contributions. Not on `yourname.github.io`: the page refuses to enroll
   there. Details in [docs/SETUP.md](docs/SETUP.md).
2. **Test your keys.** On your device, open
   `https://unlock.yourdomain.com/#selftest`. You want PASS for each key.
3. **Enroll.** Open `#enroll`, register your YubiKeys, write down the paper
   key, and commit the `config.js` it gives you to your repo. Then set an
   anti phishing phrase on the home page.
4. **Install on the agent.** Give the agent [docs/AGENT.md](docs/AGENT.md)
   and have it run:
   ```sh
   git clone https://github.com/<you>/tapseal
   cd tapseal
   pip install --user .
   tapseal init
   ```
   It also sets `TAPSEAL_URL` to your page and schedules `tapseal sweep`
   every minute.
5. **Certify the agent.** It sends you a link and a fingerprint. Open the
   link, check the fingerprint matches, tap your key, and paste the result
   back. After every reboot of the agent's server it asks again.

## Add a secret

1. On your device, open `#seal` from your bookmark. Never from a link.
2. Name it, paste the secret, and tap your key.
3. Send the `tsv1…` text it gives you to the agent. The agent stores it but
   cannot open it.
4. Tell the agent which tool uses it.

Use a fresh secret. Anything the server has ever seen unencrypted should be
treated as exposed.

## Use a secret

1. The agent sends you a link and says what it needs.
2. Tap the link, then your YubiKey.
3. Check the name and the sealed date, choose how long it stays available,
   and tap **Deliver**.
4. Paste the `tsd1…` text back to the agent.

When the time is up, the secret is deleted from the server.

## Updates

Your deploy repo checks this repo for new releases daily and opens a pull
request with the changes. Read it, then merge. Nothing reaches your page until
you do.

## Lost a key?

Open `#rotate` from your bookmark. If you lost every key, open `#recover`
instead and enter your paper key. Never enter it on a page you reached from a
link. Both make a new vault key, so lost keys and the old paper key stop
working.

## Good to know

**Limits.**
1. While a secret is unlocked, whoever runs the server can read it, including
   through a memory snapshot.
2. An agent can misuse a secret you gave it.
3. Whoever controls your chat with the agent can pretend to be you to the
   agent, and can pretend to be the agent to you. If the agent's provider also
   runs the chat, they are the same party.

Details in [docs/THREATS.md](docs/THREATS.md).

**Secrets needed around the clock**, for example by a scheduled job, can't
wait for a tap. Those stay unencrypted on the server, so give them the
smallest permissions possible.

**Requirements.** A YubiKey 5 or Bio (or any FIDO2 key with PRF) with a PIN
set. Chrome on Android, or Safari on iOS 18 and later. On the server: Linux, a
persistent shell and home directory, a tmpfs such as `/dev/shm`, cron or a
process supervisor, and Python 3.10 or newer with pip. Many hosted agents
reset their sandbox between sessions; those cannot run tapseal.

**More.** [Full setup](docs/SETUP.md), [formats](docs/SPEC.md),
[reporting security issues](SECURITY.md). Tests live in `tests`.

## License

MIT
