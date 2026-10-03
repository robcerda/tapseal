/* tapseal unlock page UI. Routes on the URL fragment (never sent to the server):
 *   #u=<tsv1 blob>&r=<tsr1 request>   unlock a sealed secret and deliver it to the VM
 *   #seal                              seal a new secret into a vault blob
 *   #enroll                            create the keyring or add keys to it
 *   #recover                           paper-key recovery: unlock the keyring, re-enroll keys
 *   #selftest                          check WebAuthn PRF on this phone + key
 */
(function () {
  'use strict';
  const C = window.TAPSEAL;
  const CFG = window.TAPSEAL_CONFIG || null;
  const app = document.getElementById('app');
  const rpId = (CFG && CFG.rpId) || location.hostname;
  const TRANSPORTS = ['usb', 'nfc'];

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
  const show = (...nodes) => app.replaceChildren(...nodes);
  const status = el('p', { class: 'status', role: 'status' });
  const card = (...kids) => el('section', { class: 'card' }, ...kids);

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

  // ---------- WebAuthn PRF ----------

  async function createCredential(label, exclude) {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: 'tapseal' },
        user: { id: C.rand(16), name: 'tapseal-' + label, displayName: 'tapseal ' + label },
        challenge: C.rand(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'cross-platform', residentKey: 'discouraged', userVerification: 'required' },
        excludeCredentials: (exclude || []).map((id) => ({ type: 'public-key', id: C.b64d(id), transports: TRANSPORTS })),
        hints: ['security-key'],
        extensions: { prf: {} },
        timeout: 120000,
      },
    });
    const prf = cred.getClientExtensionResults().prf;
    if (prf && prf.enabled === false) throw new Error('This key or browser does not support PRF.');
    return C.b64e(new Uint8Array(cred.rawId));
  }

  // Returns { slot, out, second? } for whichever enrolled key answered.
  async function prfEval(slots, secondSalt) {
    const evalByCredential = {};
    for (const s of slots) {
      evalByCredential[s.credId] = secondSalt ? { first: C.b64d(s.salt), second: secondSalt } : { first: C.b64d(s.salt) };
    }
    const a = await navigator.credentials.get({
      publicKey: {
        rpId,
        challenge: C.rand(32),
        allowCredentials: slots.map((s) => ({ type: 'public-key', id: C.b64d(s.credId), transports: TRANSPORTS })),
        userVerification: 'required',
        hints: ['security-key'],
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

  // Security-key gate that yields the vault key K. The paper key is deliberately
  // NOT offered here: links arrive from the agent, and a lookalike page could ask
  // for it. Paper recovery lives only at #recover.
  function keyGate(label, onK) {
    const tap = el('button', { class: 'primary' }, label);
    tap.addEventListener('click', busy(tap, async () => {
      setStatus('Tap or insert your security key, then verify with PIN or fingerprint.');
      const { slot, out } = await prfEval(CFG.slots);
      let K;
      try { K = await C.unwrapK(slot, out); } finally { out.fill(0); }
      setStatus('Unlocked with ' + slot.label + '.', 'ok');
      await onK(K, slot.label);
    }));
    return el('div', { class: 'row' }, tap);
  }

  function needConfig() {
    if (CFG && CFG.slots && CFG.slots.length && CFG.vmKey) return false;
    show(card(el('h2', {}, 'Not enrolled'),
      el('p', {}, 'This page has no keyring or VM key yet. Open ', el('a', { href: '#enroll' }, 'Enroll'), ' to set it up.')));
    return true;
  }

  async function vmLine() {
    return el('p', { class: 'muted' }, 'VM key ', el('code', {}, await C.fingerprint(CFG.vmKey)));
  }

  function fmtTTL(s) {
    if (s % 86400 === 0) return s / 86400 + 'd';
    if (s % 3600 === 0) return s / 3600 + 'h';
    return Math.round(s / 60) + 'm';
  }

  // ---------- views ----------

  async function viewHome() {
    const items = [el('h1', {}, 'tapseal')];
    if (CFG && CFG.slots) {
      items.push(card(
        el('p', {}, 'Keys: ' + CFG.slots.map((s) => s.label).join(', ')),
        CFG.vmKey ? await vmLine() : el('p', { class: 'bad' }, 'No VM key configured.'),
        el('p', { class: 'muted' }, 'RP ID ', el('code', {}, rpId))));
    } else {
      items.push(el('p', {}, 'Not enrolled yet.'));
    }
    items.push(el('nav', { class: 'card' },
      el('a', { href: '#seal' }, 'Seal a secret'), el('a', { href: '#enroll' }, 'Enroll keys'),
      el('a', { href: '#selftest' }, 'PRF self-test'), el('a', { href: '#recover' }, 'Recover with paper key')));
    show(...items);
  }

  async function viewUnlock(blob, reqStr) {
    if (needConfig()) return;
    let claimed, req;
    try {
      claimed = C.parseVault(blob).claimed;
      if (!reqStr) throw new Error('Link has no unlock request. Ask the agent for a new link.');
      req = await C.verifyRequest(CFG.vmKey, reqStr);
      if (req.name !== claimed.name) throw new Error('Request and secret names differ. Do not unlock.');
    } catch (e) {
      show(el('h1', {}, 'Bad link'), card(el('p', { class: 'bad' }, explain(e))));
      return;
    }

    const body = el('div');
    show(el('h1', {}, 'Unlock request'),
      card(
        el('p', {}, 'Your VM is asking for ', el('strong', {}, String(req.name)), '.'),
        el('p', { class: 'muted' }, 'Request signed by your VM, valid until ' + new Date(req.exp * 1000).toLocaleTimeString()
          + '. The secret itself is verified when you unlock.'),
        await vmLine(),
        keyGate('Unlock with security key', async (K) => {
          let sec;
          try { sec = await C.unseal(K, blob); } finally { K.fill(0); }
          if (sec.header.name !== req.name) throw new Error('Verified secret does not match the request. Nothing delivered.');
          body.replaceChildren(await confirmDelivery(sec, req));
        })),
      body, status);
  }

  async function confirmDelivery(sec, req) {
    const h = sec.header;
    const c = card(el('h2', {}, 'Verified: ' + h.name),
      el('p', {}, 'Sealed ' + new Date(h.created * 1000).toLocaleString()));
    let ttlSel = null;
    if (h.kind === 'file') {
      const opts = [...new Set([h.ttl, 3600, 900, 300].filter((t) => t <= h.ttl))].sort((a, b) => b - a);
      ttlSel = el('select', {}, opts.map((t) => el('option', { value: t }, fmtTTL(t))));
      c.append(el('label', {}, 'Live on the VM for ', ttlSel));
      c.append(el('p', { class: 'muted' }, 'Deleting the file does not revoke the credential. If this is a long-lived session, a copy taken while live stays valid until the provider expires it.'));
    } else {
      c.append(el('p', {}, 'Google: mints a 1-hour access token here. The refresh token never leaves this page.'));
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
      const tsd = await C.deliver(req, { name: h.name, kind: h.kind, exp, payload });
      data = null; payload = null;
      go.remove(); cancel.remove();
      setStatus('Delivery expires ' + new Date(exp * 1000).toLocaleTimeString() + '.', 'ok');
      out.replaceChildren(output('Paste this into chat', tsd,
        'Opens once, on your VM only. The VM deletes the key for it on receipt, so a copy in chat or logs is useless afterwards.'));
    }));
    c.append(el('div', { class: 'row' }, go, cancel));
    return el('div', {}, c, out);
  }

  function viewSeal() {
    if (needConfig()) return;
    const name = el('input', { type: 'text', placeholder: 'e.g. oura', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
    const kind = el('select', {}, el('option', { value: 'file' }, 'File / token (delivered as-is)'), el('option', { value: 'google' }, 'Google OAuth (deliver access tokens only)'));
    const ttl = el('select', {}, [300, 900, 3600, 8 * 3600, 86400].map((t) => el('option', { value: t, selected: t === 3600 }, 'max ' + fmtTTL(t))));
    const fmt = el('select', {}, el('option', { value: 'google-auth' }, 'google-auth (Python)'), el('option', { value: 'oauth2-go' }, 'oauth2 (Go)'));
    const ttlRow = el('label', {}, 'Longest allowed delivery ', ttl);
    const fmtRow = el('label', { class: 'hidden' }, 'Token format ', fmt);
    kind.addEventListener('change', () => {
      ttlRow.classList.toggle('hidden', kind.value !== 'file');
      fmtRow.classList.toggle('hidden', kind.value !== 'google');
    });
    const secret = el('textarea', { rows: 6, class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'Secret value. For Google: authorized_user JSON with refresh_token, client_id, client_secret.' });
    const out = el('div');

    show(el('h1', {}, 'Seal a secret'),
      card(
        el('label', {}, 'Name ', name), el('label', {}, 'Kind ', kind), ttlRow, fmtRow, secret,
        el('p', { class: 'muted' }, 'Issue the secret on this phone where possible. A secret that was ever on the VM is already exposed.'),
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
              'Send this to the agent to store. It is encrypted and authenticated; only your keys open it. Keep a copy somewhere safe too.'));
          } finally { K.fill(0); }
        })),
      out, status);
  }

  // Key management. mode: 'new' (fresh keyring), 'keys' (unlock with a key), 'paper' (recovery).
  function viewEnroll(mode) {
    const existing = !!(CFG && CFG.slots && CFG.slots.length);
    if (!mode) mode = existing ? 'keys' : 'new';
    if (mode === 'paper' && !(CFG && CFG.paper)) {
      show(el('h1', {}, 'Recover'), card(el('p', {}, 'No paper key is configured on this page.')));
      return;
    }
    let K = null;
    const slots = existing ? CFG.slots.slice() : [];
    let paperSlot = existing ? CFG.paper : null;
    let paperShown = null;

    const list = el('ul');
    const renderList = () => list.replaceChildren(...slots.map((s, i) => el('li', {}, s.label + ' ',
      el('button', { onclick: () => { slots.splice(i, 1); renderList(); } }, 'Remove'))));
    renderList();

    const label = el('input', { type: 'text', placeholder: 'e.g. yk-nfc, yk-bio', autocomplete: 'off', autocapitalize: 'none' });
    const add = el('button', { class: 'primary' }, 'Register key');
    add.addEventListener('click', busy(add, async () => {
      const l = label.value.trim();
      if (!/^[\w-]{1,32}$/.test(l)) throw new Error('Give the key a short label.');
      if (slots.some((s) => s.label === l)) throw new Error('Label already used.');
      setStatus('Touch 1 of 2: register the key.');
      const credId = await createCredential(l, slots.map((s) => s.credId));
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

    const vmKey = el('input', { type: 'text', class: 'mono', placeholder: 'from: tapseal init', value: (CFG && CFG.vmKey) || '', autocomplete: 'off', spellcheck: 'false' });
    const rotatePaper = el('input', { type: 'checkbox', checked: mode === 'paper' });
    const paperBox = el('div');
    const wrote = el('input', { type: 'checkbox' });
    const gen = el('button', { class: 'primary' }, 'Generate config.js');
    const out = el('div');

    async function ensurePaper() {
      if (paperSlot && !rotatePaper.checked) return;
      if (paperShown) return;
      const p = C.rand(32);
      paperSlot = await C.wrapK(K, p);
      paperShown = C.paperEncode(p);
      p.fill(0);
      paperBox.replaceChildren(el('section', { class: 'card warn' },
        el('h2', {}, 'Paper key: write it down now'),
        el('p', { class: 'paper mono' }, paperShown),
        el('p', {}, 'Shown once. It opens everything, alone. Store it offline, away from your keys.'),
        el('label', {}, wrote, ' I wrote it down and checked it')));
    }

    gen.addEventListener('click', busy(gen, async () => {
      if (!slots.length) throw new Error('Register at least one key (two recommended).');
      await C.importIdentity(vmKey.value.trim());
      await ensurePaper();
      if (paperShown && !wrote.checked) throw new Error('Confirm you wrote down the paper key.');
      const cfg = { v: 1, rpId, vmKey: vmKey.value.trim(), slots, paper: paperSlot };
      const text = 'window.TAPSEAL_CONFIG = ' + JSON.stringify(cfg, null, 2) + ';\n';
      out.replaceChildren(output('config.js', text,
        'Replace site/config.js in your repo with this and redeploy. Contains no secrets: every slot is wrapped.'
        + (slots.length < 2 ? ' Warning: only one key enrolled.' : '')));
    }));

    const setup = el('div', { class: 'hidden' },
      card(el('h2', {}, 'Keys'), list,
        el('p', { class: 'muted' }, 'Each key takes two touches. Remove keys you lost.'),
        el('div', { class: 'row' }, label, add)),
      card(el('h2', {}, 'VM identity key'), vmKey,
        existing ? el('label', {}, rotatePaper, ' Generate a new paper key (old one stops working)') : null,
        el('div', { class: 'row' }, gen)),
      paperBox, out);

    const open = (k) => { K = k; start.remove(); setup.classList.remove('hidden'); };
    let start;
    if (mode === 'new') {
      const b = el('button', { class: 'primary', onclick: () => open(C.rand(32)) }, 'Start');
      start = card(el('h2', {}, 'New keyring'),
        el('p', {}, 'Creates a new vault key. Blobs sealed under any previous keyring will not open.'),
        el('div', { class: 'row' }, b));
    } else if (mode === 'keys') {
      start = card(el('h2', {}, 'Unlock the existing keyring to change keys'), keyGate('Unlock with an enrolled key', async (k) => open(k)),
        el('p', { class: 'muted' }, 'Lost your keys? ', el('a', { href: '#recover' }, 'Recover with the paper key'), '.'));
    } else {
      const paperIn = el('input', { type: 'text', placeholder: 'XXXX-XXXX-...', autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', class: 'mono' });
      const paperBtn = el('button', { class: 'primary' }, 'Unlock with paper key');
      paperBtn.addEventListener('click', busy(paperBtn, async () => {
        let k;
        try { k = await C.unwrapK(CFG.paper, C.paperDecode(paperIn.value)); }
        catch { throw new Error('Paper key did not match.'); }
        paperIn.value = '';
        setStatus('Paper key accepted. Register replacement keys, remove lost ones, and generate a new config.', 'ok');
        open(k);
      }));
      start = el('section', { class: 'card warn' }, el('h2', {}, 'Paper key recovery'),
        el('p', {}, 'Only type your paper key here if you opened this page yourself, by typing its address. '
          + 'A link from chat or email should never lead to this page. If one did, stop.'),
        el('p', { class: 'muted' }, 'Check the address bar: ', el('code', {}, location.host)),
        el('div', { class: 'row' }, paperIn, paperBtn));
    }

    show(el('h1', {}, mode === 'paper' ? 'Recover' : 'Enroll'),
      el('p', { class: 'muted' }, 'RP ID ', el('code', {}, rpId), ': keys enrolled here only work on this domain.'),
      start, setup, status);
  }

  function viewSelftest() {
    const run = el('button', { class: 'primary' }, 'Run self-test');
    const log = el('ul');
    const say = (t, cls) => log.append(el('li', { class: cls || '' }, t));
    run.addEventListener('click', busy(run, async () => {
      log.replaceChildren();
      say('Touch 1 of 3: create a throwaway credential (non-resident; uses no slot on the key).');
      const credId = await createCredential('selftest');
      const slot = { label: 'selftest', credId, salt: C.b64e(C.rand(32)) };
      const salt2 = C.rand(32);
      say('Touch 2 of 3: evaluate PRF with two salts.');
      const a = await prfEval([slot], salt2);
      say('Touch 3 of 3: evaluate again.');
      const b = await prfEval([slot]);
      const same = C.b64e(a.out) === C.b64e(b.out);
      const diff = a.second && C.b64e(a.out) !== C.b64e(a.second);
      say(same ? 'PRF is stable across touches.' : 'PRF output changed between touches.', same ? 'ok' : 'bad');
      say(a.second ? (diff ? 'Different salts give different outputs.' : 'Salts collided.') : 'Second salt not returned (fine).', a.second && !diff ? 'bad' : 'ok');
      say(same ? 'PASS: this phone and key can run tapseal.' : 'FAIL', same ? 'ok' : 'bad');
    }));
    show(el('h1', {}, 'PRF self-test'),
      card(el('p', {}, 'Run once per phone and key combination before enrolling.'), el('div', { class: 'row' }, run), log),
      status);
  }

  function route() {
    setStatus('');
    const h = location.hash.slice(1);
    if (h.startsWith('u=')) {
      const q = new URLSearchParams(h);
      return viewUnlock(q.get('u'), q.get('r'));
    }
    if (h === 'seal') return viewSeal();
    if (h === 'enroll') return viewEnroll();
    if (h === 'recover') return viewEnroll('paper');
    if (h === 'selftest') return viewSelftest();
    return viewHome();
  }

  // Hosts without header control (GitHub Pages) cannot send frame-ancestors; refuse framing here.
  if (window.top !== window.self) {
    show(el('p', { class: 'bad' }, 'tapseal refuses to run inside a frame. Open it directly.'));
    return;
  }
  if (!window.PublicKeyCredential || !window.isSecureContext) {
    show(el('p', { class: 'bad' }, 'WebAuthn unavailable. Open this page in Safari or Chrome over HTTPS, not an in-app browser.'));
    return;
  }
  const go = () => Promise.resolve().then(route).catch((e) => setStatus(explain(e), 'bad'));
  window.addEventListener('hashchange', go);
  go();
})();
