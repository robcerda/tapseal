/* tapseal unlock page UI. Routes on the URL fragment (never sent to the server):
 *   #u=<tsv1>&c=<tsc1>&r=<tsr1>   unlock a sealed secret and deliver it to the VM
 *   #certify=<VM identity key>    vouch for the VM's identity after it (re)starts
 *   #seal                         seal a new secret
 *   #enroll                       create the keyring, or add keys to it
 *   #rotate                       new vault key: revoke lost keys or an old paper key
 *   #recover                      paper key recovery, which always rotates
 *   #selftest                     check WebAuthn PRF on this device + key
 */
(function () {
  'use strict';
  const C = window.TAPSEAL;
  const CFG = window.TAPSEAL_CONFIG || null;
  const app = document.getElementById('app');
  const rpId = (CFG && CFG.rpId) || location.hostname;
  const TRANSPORTS = ['usb', 'nfc'];
  const PHRASE_KEY = 'tapseal-phrase';

  // ---------- tiny DOM helpers ----------

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') n.className = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (v === true) n.setAttribute(k, '');
      else if (v !== false && v != null) n.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return n;
  }
  const status = el('p', { class: 'status', role: 'status' });
  const card = (...kids) => el('section', { class: 'card' }, ...kids);
  const warn = (...kids) => el('section', { class: 'card warn' }, ...kids);
  const input = (attrs) => el('input', { type: 'text', autocomplete: 'off', autocorrect: 'off', autocapitalize: 'none', spellcheck: 'false', ...attrs });

  function phrase() {
    try { return localStorage.getItem(PHRASE_KEY) || ''; } catch { return ''; }
  }

  // Every view shows this device's anti phishing phrase. A lookalike page cannot know it.
  function show(...nodes) {
    const p = phrase();
    app.replaceChildren(...[p ? el('p', { class: 'phrase' }, '🔒 ' + p) : null, ...nodes].filter((x) => x != null));
  }

  function setStatus(msg, kind) {
    status.textContent = msg || '';
    status.className = 'status' + (kind ? ' ' + kind : '');
  }

  function explain(e) {
    if (e && e.name === 'NotAllowedError') return 'Cancelled, timed out, or the key was not recognised.';
    if (e && e.name === 'InvalidStateError') return 'That key is already registered.';
    return (e && e.message) || String(e);
  }

  function busy(btn, fn) {
    return async () => {
      btn.disabled = true;
      setStatus('');
      try { await fn(); } catch (e) { setStatus(explain(e), 'bad'); } finally { btn.disabled = false; }
    };
  }

  function output(title, text, note) {
    const ta = el('textarea', { readonly: true, rows: 6, class: 'mono', spellcheck: 'false' });
    ta.value = text;
    const copy = el('button', { class: 'primary' }, 'Copy');
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(text); copy.textContent = 'Copied'; }
      catch { ta.select(); setStatus('Copy failed; select the text and copy manually.', 'bad'); }
    });
    const row = el('div', { class: 'row' }, copy);
    if (navigator.share) {
      const share = el('button', {}, 'Share');
      share.addEventListener('click', () => navigator.share({ text }).catch(() => {}));
      row.append(share);
    }
    return card(el('h2', {}, title), note ? el('p', {}, note) : null, ta, row);
  }

  function ago(ts) {
    const d = C.now() - ts;
    if (d < 3600) return Math.max(0, Math.round(d / 60)) + ' minutes ago';
    if (d < 86400 * 2) return Math.round(d / 3600) + ' hours ago';
    return Math.round(d / 86400) + ' days ago';
  }

  function until(ts) {
    const d = ts - C.now();
    if (d < 3600) return 'in ' + Math.max(0, Math.round(d / 60)) + ' minutes';
    if (d < 86400 * 2) return 'in ' + Math.round(d / 3600) + ' hours';
    return 'in ' + Math.round(d / 86400) + ' days';
  }

  function fmtTTL(s) {
    if (s % 86400 === 0) return s / 86400 + 'd';
    if (s % 3600 === 0) return s / 3600 + 'h';
    return Math.round(s / 60) + 'm';
  }

  // ---------- WebAuthn PRF ----------

  // any: accept platform authenticators and passkey providers too (self test only).
  // Enrollment always requires a roaming hardware security key.
  async function createCredential(label, exclude, any) {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: 'tapseal' },
        user: { id: C.rand(16), name: 'tapseal-' + label, displayName: 'tapseal ' + label },
        challenge: C.rand(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: any
          ? { residentKey: 'discouraged', userVerification: 'required' }
          : { authenticatorAttachment: 'cross-platform', residentKey: 'discouraged', userVerification: 'required' },
        excludeCredentials: (exclude || []).map((id) => ({ type: 'public-key', id: C.b64d(id), transports: TRANSPORTS })),
        hints: any ? [] : ['security-key'],
        extensions: { prf: {} },
        timeout: 120000,
      },
    });
    const prf = cred.getClientExtensionResults().prf;
    if (prf && prf.enabled === false) throw new Error('This authenticator or browser does not support PRF.');
    return { credId: C.b64e(new Uint8Array(cred.rawId)), attachment: cred.authenticatorAttachment || 'unknown' };
  }

  // Returns { slot, out, second? } for whichever enrolled key answered.
  async function prfEval(slots, secondSalt, any) {
    const evalByCredential = {};
    for (const s of slots) {
      evalByCredential[s.credId] = secondSalt ? { first: C.b64d(s.salt), second: secondSalt } : { first: C.b64d(s.salt) };
    }
    const a = await navigator.credentials.get({
      publicKey: {
        rpId,
        challenge: C.rand(32),
        allowCredentials: slots.map((s) => (any ? { type: 'public-key', id: C.b64d(s.credId) }
          : { type: 'public-key', id: C.b64d(s.credId), transports: TRANSPORTS })),
        userVerification: 'required',
        hints: any ? [] : ['security-key'],
        extensions: { prf: { evalByCredential } },
        timeout: 120000,
      },
    });
    const res = (a.getClientExtensionResults().prf || {}).results;
    if (!res || !res.first) throw new Error('No PRF output. This browser or key does not support PRF here.');
    const id = C.b64e(new Uint8Array(a.rawId));
    const slot = slots.find((s) => s.credId === id);
    if (!slot) throw new Error('Unexpected credential answered.');
    return { slot, out: new Uint8Array(res.first), second: res.second ? new Uint8Array(res.second) : null };
  }

  // Security key gate yielding K and the page signing key. The paper key is deliberately
  // NOT offered here: links arrive from the agent, and a lookalike page could ask for it.
  function keyGate(label, onOpen) {
    const tap = el('button', { class: 'primary' }, label);
    tap.addEventListener('click', busy(tap, async () => {
      setStatus('Tap or insert your security key, then verify with PIN or fingerprint.');
      const { slot, out } = await prfEval(CFG.slots);
      let K;
      try { K = await C.unwrapK(slot, out); } finally { out.fill(0); }
      const signer = await C.openPageKey(K, CFG.pageSeal);
      setStatus('Unlocked with ' + slot.label + '.', 'ok');
      await onOpen(K, signer, slot.label);
    }));
    return el('div', { class: 'row' }, tap);
  }

  function needConfig() {
    if (CFG && CFG.slots && CFG.slots.length && CFG.pageKey && CFG.pageSeal) return false;
    show(card(el('h2', {}, 'Not enrolled'),
      el('p', {}, 'This page has no keyring yet. Open ', el('a', { href: '#enroll' }, 'Enroll'), ' to set it up.')));
    return true;
  }

  // ---------- views ----------

  async function viewHome() {
    const items = [el('h1', {}, 'tapseal')];
    if (CFG && CFG.slots) {
      items.push(card(
        el('p', {}, 'Keys: ' + CFG.slots.map((s) => s.label).join(', ')),
        el('p', { class: 'muted' }, 'Page key ', el('code', {}, await C.fingerprint(CFG.pageKey))),
        el('p', { class: 'muted' }, 'RP ID ', el('code', {}, rpId))));
    } else {
      items.push(el('p', {}, 'Not enrolled yet.'));
    }
    const ph = input({ placeholder: 'e.g. blue heron', value: phrase() });
    const save = el('button', {}, 'Save phrase');
    save.addEventListener('click', () => {
      try { localStorage.setItem(PHRASE_KEY, ph.value.trim()); route(); }
      catch { setStatus('This browser would not store the phrase.', 'bad'); }
    });
    items.push(card(el('h2', {}, 'Anti phishing phrase'),
      el('p', { class: 'muted' }, 'Stored only on this device and shown at the top of every view. If a page claiming to be tapseal does not show it, close it.'),
      el('div', { class: 'row' }, ph, save)));
    items.push(el('nav', { class: 'card' },
      el('a', { href: '#seal' }, 'Seal a secret'), el('a', { href: '#enroll' }, 'Enroll or add keys'),
      el('a', { href: '#rotate' }, 'Rotate vault key'), el('a', { href: '#selftest' }, 'PRF self test'),
      el('a', { href: '#recover' }, 'Recover with paper key')));
    show(...items, status);
  }

  async function viewUnlock(blob, certStr, reqStr) {
    if (needConfig()) return;
    let claimed, cert, req;
    try {
      claimed = C.parseVault(blob).claimed;
      if (!certStr || !reqStr) throw new Error('Link is incomplete. Ask the agent for a new link.');
      cert = await C.verifyCert(CFG.pageKey, certStr);
      req = await C.verifyRequest(cert.vmKey, reqStr);
      if (req.name !== claimed.name) throw new Error('Request and secret names differ. Do not unlock.');
    } catch (e) {
      show(el('h1', {}, 'Bad link'), card(el('p', { class: 'bad' }, explain(e))));
      return;
    }

    const body = el('div');
    show(el('h1', {}, 'Unlock request'),
      card(
        el('p', {}, 'Your VM is asking for ', el('strong', {}, String(req.name)), '.'),
        el('p', { class: 'muted' }, 'Request expires ' + until(req.exp) + '. VM identity ',
          el('code', {}, await C.fingerprint(cert.vmKey)), ', certified until ' + new Date(cert.exp * 1000).toLocaleDateString() + '.'),
        keyGate('Unlock with security key', async (K, signer) => {
          let sec;
          try { sec = await C.unseal(K, blob); } finally { K.fill(0); }
          if (sec.header.name !== req.name) throw new Error('Verified secret does not match the request. Nothing delivered.');
          body.replaceChildren(await confirmDelivery(sec, req, signer));
        })),
      body, status);
  }

  async function confirmDelivery(sec, req, signer) {
    const h = sec.header;
    const c = card(el('h2', {}, 'Verified: ' + h.name),
      el('p', { class: 'sealed' }, 'Sealed ' + ago(h.created) + ' (' + new Date(h.created * 1000).toLocaleDateString() + ')'),
      el('p', { class: 'muted' }, 'If you sealed a newer version of this secret, this is an old copy. Cancel.'));
    let ttlSel = null;
    if (h.kind === 'file') {
      const opts = [...new Set([300, 900, 3600, h.ttl].filter((t) => t <= h.ttl))].sort((a, b) => a - b);
      ttlSel = el('select', {}, opts.map((t, i) => el('option', { value: t, selected: i === 0 }, fmtTTL(t))));
      c.append(el('label', {}, 'Live on the VM for ', ttlSel));
      c.append(el('p', { class: 'muted' }, 'Deleting the file does not revoke the credential. If this is a long lived session, a copy taken while live stays valid until the provider expires it.'));
    } else {
      c.append(el('p', {}, 'Google: mints a 1 hour access token here. The refresh token never leaves this page.'));
    }
    const go = el('button', { class: 'primary' }, 'Deliver to VM');
    const cancel = el('button', {}, 'Cancel');
    const out = el('div');
    let data = sec.data;
    sec.data = null;
    cancel.addEventListener('click', () => { data = null; location.hash = ''; });
    go.addEventListener('click', busy(go, async () => {
      if (data == null) throw new Error('Already delivered or cancelled. Ask the agent for a new link.');
      if (req.exp <= C.now()) throw new Error('The unlock request expired. Ask the agent for a new link.');
      let payload, exp;
      if (h.kind === 'google') ({ payload, exp } = await C.mintGoogle(data, h.fmt));
      else { payload = data; exp = C.now() + Number(ttlSel.value); }
      const tsd = await C.deliver(req, signer, { name: h.name, kind: h.kind, exp, payload });
      data = null; payload = null;
      go.remove(); cancel.remove();
      setStatus('Delivery expires ' + until(exp) + '.', 'ok');
      out.replaceChildren(output('Paste this into chat', tsd,
        'Opens once, on your VM only, and only because your key signed it. A copy in chat or logs is useless afterwards.'));
    }));
    c.append(el('div', { class: 'row' }, go, cancel));
    return el('div', {}, c, out);
  }

  async function viewCertify(vmKey) {
    if (needConfig()) return;
    let fp;
    try { const raw = C.b64d(vmKey); if (raw.length !== 65 || raw[0] !== 4) throw new Error(); fp = await C.fingerprint(vmKey); }
    catch { show(el('h1', {}, 'Bad link'), card(el('p', { class: 'bad' }, 'Not a VM identity key.'))); return; }
    const life = el('select', {}, [[7, '7 days'], [30, '30 days'], [90, '90 days']].map(([d, t]) =>
      el('option', { value: d * 86400, selected: d === 30 }, t)));
    const out = el('div');
    show(el('h1', {}, 'Certify VM identity'),
      warn(el('p', {}, 'Certify only if your agent just started or restarted and asked you for this, in your usual chat. '
        + 'Anyone you certify can request your secrets.'),
        el('p', {}, 'Identity fingerprint: ', el('code', {}, fp)),
        el('p', { class: 'muted' }, 'It must match the fingerprint the agent printed.')),
      card(el('label', {}, 'Valid for ', life),
        keyGate('Certify with security key', async (K, signer) => {
          K.fill(0);
          const cert = await C.certify(signer, CFG.pageKey, vmKey, Number(life.value));
          out.replaceChildren(output('Paste this into chat', cert,
            'The agent runs: tapseal certify. Contains no secrets.'));
        })),
      out, status);
  }

  function viewSeal() {
    if (needConfig()) return;
    const name = input({ placeholder: 'e.g. oura' });
    const kind = el('select', {}, el('option', { value: 'file' }, 'File / token (delivered as is)'), el('option', { value: 'google' }, 'Google OAuth (deliver access tokens only)'));
    const ttl = el('select', {}, [300, 900, 3600, 8 * 3600, 86400].map((t) => el('option', { value: t, selected: t === 3600 }, 'max ' + fmtTTL(t))));
    const fmt = el('select', {}, el('option', { value: 'google-auth' }, 'google-auth (Python)'), el('option', { value: 'oauth2-go' }, 'oauth2 (Go)'));
    const ttlRow = el('label', {}, 'Longest allowed delivery ', ttl);
    const fmtRow = el('label', { class: 'hidden' }, 'Token format ', fmt);
    kind.addEventListener('change', () => {
      ttlRow.classList.toggle('hidden', kind.value !== 'file');
      fmtRow.classList.toggle('hidden', kind.value !== 'google');
    });
    const secret = el('textarea', { rows: 6, class: 'mono', autocomplete: 'off', autocorrect: 'off', autocapitalize: 'none', spellcheck: 'false', placeholder: 'Secret value. For Google: authorized_user JSON with refresh_token, client_id, client_secret.' });
    const out = el('div');

    show(el('h1', {}, 'Seal a secret'),
      warn(el('p', {}, 'Only seal on a page you opened from your own bookmark. Never seal on a page reached from a link.')),
      card(
        el('label', {}, 'Name ', name), el('label', {}, 'Kind ', kind), ttlRow, fmtRow, secret,
        el('p', { class: 'muted' }, 'Issue the secret on this device where possible, and clear your clipboard after pasting. A secret that was ever on the VM is already exposed.'),
        keyGate('Seal with security key', async (K) => {
          try {
            if (!C.NAME_RE.test(name.value)) throw new Error('Name must be a-z, 0-9, _ or -.');
            if (!secret.value) throw new Error('Nothing to seal.');
            if (kind.value === 'google') {
              const j = JSON.parse(secret.value);
              if (!j.refresh_token || !j.client_id) throw new Error('Google JSON needs refresh_token and client_id.');
            }
            const blob = await C.seal(K, { name: name.value, kind: kind.value, ttl: Number(ttl.value), fmt: fmt.value, data: secret.value });
            secret.value = '';
            out.replaceChildren(output('Vault blob for ' + name.value, blob,
              'Send this to the agent to store. It is encrypted and authenticated; only your keys open it.'));
          } finally { K.fill(0); }
        })),
      out, status);
  }

  // Key management.
  //   'new'    fresh keyring
  //   'add'    unlock with a key, add more keys (same vault key)
  //   'rotate' new vault key and page key; old keys, old paper key, and old config.js stop working
  // gate: 'key' or 'paper' (how to open the current keyring for 'add' and 'rotate')
  function viewEnroll(mode, gate) {
    if (location.hostname.endsWith('.github.io')) {
      show(el('h1', {}, 'Use your own domain'),
        warn(el('p', {}, 'Enrolling on ' + location.hostname + ' would bind your keys to an origin every GitHub Pages site on this account shares. '
          + 'Any of them could use your keys. Set up a custom subdomain first (docs/SETUP.md).')));
      return;
    }
    if (mode !== 'new' && !(CFG && CFG.slots && CFG.slots.length)) {
      show(el('h1', {}, 'Not enrolled'), card(el('p', {}, 'There is no keyring to change yet. ', el('a', { href: '#enroll' }, 'Enroll'), '.')));
      return;
    }
    if (gate === 'paper' && !(CFG && CFG.paper)) {
      show(el('h1', {}, 'Recover'), card(el('p', {}, 'No paper key is configured on this page.')));
      return;
    }

    let K = null, oldK = null, page = null;
    const slots = mode === 'add' ? CFG.slots.slice() : [];
    let paperSlot = mode === 'add' ? CFG.paper : null;
    let paperShown = null;

    const list = el('ul');
    const renderList = () => list.replaceChildren(...slots.map((s) => el('li', {}, s.label)));
    renderList();

    const label = input({ placeholder: 'e.g. yk-nfc, yk-bio' });
    const add = el('button', { class: 'primary' }, 'Register key');
    add.addEventListener('click', busy(add, async () => {
      const l = label.value.trim();
      if (!/^[\w-]{1,32}$/.test(l)) throw new Error('Give the key a short label.');
      if (slots.some((s) => s.label === l)) throw new Error('Label already used.');
      setStatus('Touch 1 of 2: register the key.');
      const { credId } = await createCredential(l, slots.map((s) => s.credId));
      const slot = { label: l, credId, salt: C.b64e(C.rand(32)) };
      setStatus('Touch 2 of 2: derive its secret.');
      const { out } = await prfEval([slot]);
      Object.assign(slot, await C.wrapK(K, out));
      out.fill(0);
      slots.push(slot);
      renderList();
      label.value = '';
      setStatus('Registered ' + l + '.', 'ok');
    }));

    const bundleIn = el('textarea', { rows: 4, class: 'mono', spellcheck: 'false', placeholder: 'tsb1... from: tapseal export' });
    const paperBox = el('div');
    const wrote = el('input', { type: 'checkbox' });
    const gen = el('button', { class: 'primary' }, 'Generate config.js');
    const out = el('div');

    async function ensurePaper() {
      if (paperSlot || paperShown) return;
      const p = C.rand(32);
      paperSlot = await C.wrapK(K, p);
      paperShown = C.paperEncode(p);
      p.fill(0);
      paperBox.replaceChildren(warn(
        el('h2', {}, 'Paper key: write it down now'),
        el('p', { class: 'paper mono' }, paperShown),
        el('p', {}, 'Shown once. It opens everything, alone. Store it offline, away from your keys.'),
        el('label', {}, wrote, ' I wrote it down and checked it')));
    }

    gen.addEventListener('click', busy(gen, async () => {
      if (!slots.length) throw new Error('Register at least one key (two recommended).');
      let bundle = null;
      if (mode === 'rotate' && bundleIn.value.trim()) bundle = await C.reseal(oldK, K, bundleIn.value);
      await ensurePaper();
      if (paperShown && !wrote.checked) throw new Error('Confirm you wrote down the paper key.');
      const cfg = { v: 1, rpId, pageKey: page.pageKey, pageSeal: page.pageSeal, slots, paper: paperSlot };
      const text = 'window.TAPSEAL_CONFIG = ' + JSON.stringify(cfg, null, 2) + ';\n';
      const outs = [output('config.js', text,
        'Replace site/config.js in your repo with this and commit. Contains no secrets.'
        + (slots.length < 2 ? ' Warning: only one key enrolled.' : ''))];
      if (mode === 'rotate') {
        outs.push(bundle
          ? output('Re-sealed secrets for the agent', bundle, 'After committing config.js, send this to the agent with: '
            + 'run tapseal import, tapseal repin, tapseal init --force, then send me the certify link.')
          : warn(el('p', {}, 'No bundle pasted: secrets sealed under the old vault key will not open with the new one.')));
        outs.push(warn(el('p', {}, 'Old blobs survive in the VM\'s backups and still open with the old vault key. '
          + 'If a key or paper key may be in someone else\'s hands, re-issue the underlying secrets too.')));
      }
      out.replaceChildren(...outs);
    }));

    const setup = el('div', { class: 'hidden' },
      card(el('h2', {}, 'Keys'), list,
        el('p', { class: 'muted' }, mode === 'rotate'
          ? 'Register every key you still have, again. Keys you do not register here stop working.'
          : 'Each key takes two touches.'),
        el('div', { class: 'row' }, label, add)),
      mode === 'rotate' ? card(el('h2', {}, 'Secrets to carry over'),
        el('p', { class: 'muted' }, 'Ask the agent for: tapseal export. Paste the tsb1 string here.'), bundleIn) : null,
      card(el('div', { class: 'row' }, gen)),
      paperBox, out);

    let start;
    const begin = async (k) => {
      if (mode === 'new') {
        K = C.rand(32);
      } else if (mode === 'add') {
        K = k;
      } else {
        oldK = k;
        K = C.rand(32);
      }
      page = mode === 'add' ? { pageKey: CFG.pageKey, pageSeal: CFG.pageSeal } : await C.newPageKey(K);
      start.remove();
      setup.classList.remove('hidden');
    };

    if (mode === 'new') {
      start = card(el('h2', {}, 'New keyring'),
        el('p', {}, 'Creates a new vault key. Blobs sealed under any previous keyring will not open.'),
        el('div', { class: 'row' }, el('button', { class: 'primary', onclick: () => begin() }, 'Start')));
    } else if (gate === 'paper') {
      const paperIn = input({ placeholder: 'XXXX-XXXX-...', autocapitalize: 'characters', class: 'mono' });
      const paperBtn = el('button', { class: 'primary' }, 'Unlock with paper key');
      paperBtn.addEventListener('click', busy(paperBtn, async () => {
        let k;
        try { k = await C.unwrapK(CFG.paper, C.paperDecode(paperIn.value)); }
        catch { throw new Error('Paper key did not match.'); }
        paperIn.value = '';
        setStatus('Paper key accepted. Register your keys to finish rotating.', 'ok');
        await begin(k);
      }));
      start = warn(el('h2', {}, 'Paper key recovery'),
        el('p', {}, 'Only type your paper key here if you opened this page yourself, from a bookmark or by typing https:// and its address. '
          + 'A link from chat or email should never lead to this page. If one did, stop.'),
        el('p', { class: 'muted' }, 'Check the address bar: ', el('code', {}, location.host),
          '. Recovery always rotates the vault key, so lost keys stop working.'),
        el('div', { class: 'row' }, paperIn, paperBtn));
    } else {
      start = card(el('h2', {}, mode === 'add' ? 'Unlock the keyring to add keys' : 'Unlock the keyring to rotate it'),
        mode === 'rotate' ? el('p', {}, 'Makes a new vault key and page key. Your old keys, old paper key, and every old config.js stop working.') : null,
        keyGate('Unlock with an enrolled key', async (k) => begin(k)),
        el('p', { class: 'muted' }, 'Lost your keys? ', el('a', { href: '#recover' }, 'Recover with the paper key'), '.'));
    }

    const titles = { new: 'Enroll', add: 'Add keys', rotate: gate === 'paper' ? 'Recover' : 'Rotate vault key' };
    show(el('h1', {}, titles[mode]),
      el('p', { class: 'muted' }, 'RP ID ', el('code', {}, rpId), ': keys enrolled here only work on this domain.'),
      start, setup, status);
  }

  function viewSelftest() {
    const run = el('button', { class: 'primary' }, 'Run self test');
    const log = el('ul');
    const say = (t, cls) => log.append(el('li', { class: cls || '' }, t));
    run.addEventListener('click', busy(run, async () => {
      log.replaceChildren();
      const step = async (label, fn) => {
        say(label);
        try { return await fn(); } catch (e) { say('Failed at: ' + label + ' ' + explain(e), 'bad'); throw e; }
      };
      const { credId, attachment } = await step('Step 1 of 4: create a throwaway credential (on a security key it is non resident and uses no slot).',
        () => createCredential('selftest', [], true));
      say('Authenticator: ' + (attachment === 'cross-platform' ? 'security key' : attachment === 'platform'
        ? 'this device or a passkey provider (synced passkey)' : 'unknown type'));
      const slot = { label: 'selftest', credId, salt: C.b64e(C.rand(32)) };
      const a = await step('Step 2 of 4: sign in and evaluate PRF with one salt (what tapseal uses).',
        () => prfEval([slot], null, true));
      const b = await step('Step 3 of 4: sign in again with the same salt.', () => prfEval([slot], null, true));
      const same = C.b64e(a.out) === C.b64e(b.out);
      say(same ? 'PRF is stable across sign ins.' : 'PRF output changed between sign ins.', same ? 'ok' : 'bad');
      say(same ? 'PASS: this device and authenticator support what tapseal needs.' : 'FAIL', same ? 'ok' : 'bad');
      if (same && attachment !== 'cross-platform') {
        say('Enrollment still accepts only hardware security keys. This result only shows the authenticator supports PRF.', 'muted');
      }
      if (!same) return;
      say('Step 4 of 4 (optional, tapseal does not need it): evaluate two salts at once.');
      try {
        const c = await prfEval([slot], C.rand(32), true);
        if (!c.second) say('Second salt not returned. Fine for tapseal.', 'muted');
        else if (C.b64e(c.out) !== C.b64e(a.out)) say('First output differs from step 2.', 'bad');
        else say(C.b64e(c.out) !== C.b64e(c.second) ? 'Two salts work and give different outputs.' : 'Salts collided.',
          C.b64e(c.out) !== C.b64e(c.second) ? 'ok' : 'bad');
      } catch (e) {
        say('Two salts at once were refused (' + explain(e) + '). Fine for tapseal.', 'muted');
      }
    }));
    show(el('h1', {}, 'PRF self test'),
      card(el('p', {}, 'Run once per device and key combination before enrolling. '
        + 'Accepts any passkey or security key, so you can check PRF support; enrollment still requires a hardware security key.'),
        el('div', { class: 'row' }, run), log),
      status);
  }

  function route() {
    setStatus('');
    const h = location.hash.slice(1);
    if (h.startsWith('u=')) {
      const q = new URLSearchParams(h);
      return viewUnlock(q.get('u'), q.get('c'), q.get('r'));
    }
    if (h.startsWith('certify=')) return viewCertify(h.slice('certify='.length));
    if (h === 'seal') return viewSeal();
    if (h === 'enroll') return viewEnroll(CFG && CFG.slots && CFG.slots.length ? 'add' : 'new', 'key');
    if (h === 'rotate') return viewEnroll('rotate', 'key');
    if (h === 'recover') return viewEnroll('rotate', 'paper');
    if (h === 'selftest') return viewSelftest();
    return viewHome();
  }

  // Hosts without header control (GitHub Pages) cannot send frame-ancestors; refuse framing here.
  if (window.top !== window.self) {
    app.replaceChildren(el('p', { class: 'bad' }, 'tapseal refuses to run inside a frame. Open it directly.'));
    return;
  }
  // Credentials are bound to CFG.rpId. Anywhere else, this page is a copy and must not run.
  if (CFG && CFG.rpId && CFG.rpId !== location.hostname) {
    app.replaceChildren(el('p', { class: 'bad' }, 'This page is configured for ' + CFG.rpId + ' but was opened on '
      + location.hostname + '. Refusing to run.'));
    return;
  }
  if (!window.PublicKeyCredential || !window.isSecureContext) {
    app.replaceChildren(el('p', { class: 'bad' }, 'WebAuthn unavailable. Open this page in Safari or Chrome over HTTPS, not an in-app browser.'));
    return;
  }
  const go = () => Promise.resolve().then(route).catch((e) => setStatus(explain(e), 'bad'));
  window.addEventListener('hashchange', go);
  go();
})();
