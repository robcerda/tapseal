/* tapseal unlock page UI. Routes on the URL fragment (never sent to the server):
 *   #u=<tsv1>&c=<tsc1>&r=<tsr1>   unlock a sealed secret and deliver it to the VM
 *   #certify=<VM identity key>    vouch for the VM's identity after it (re)starts
 *   #seal                         seal a new secret
 *   #enroll                       create the keyring, or add keys to it
 *   #rotate                       new vault key: revoke lost keys or an old paper key
 *   #recover                      paper key recovery, which always rotates
 *   #selftest                     check WebAuthn PRF on this device + key
 *   #revoke                       refuse every VM certificate issued before now
 */
(async function () {
  'use strict';
  const C = window.TAPSEAL;
  const app = document.getElementById('app');
  // Fetched, not a cached script: a stale keyring after enrolling, rotating, or revoking is a hazard.
  let CFG = null;
  try {
    const r = await fetch('config.json', { cache: 'no-store' });
    if (r.ok) CFG = await r.json();
  } catch { /* not enrolled, or offline */ }
  const V2 = !!(CFG && CFG.v === 2);
  const WRAPS_MIN = 8;
  const rpId = (CFG && CFG.rpId) || location.hostname;
  const TRANSPORTS = ['usb', 'nfc'];
  const PHRASE_KEY = 'tapseal-phrase';
  const CERTLOG_KEY = 'tapseal-certs';
  let routeGen = 0;

  // Per device memory. Best effort: storage can be missing or wiped, so nothing depends on it.
  function store(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key)) || fallback; } catch { return fallback; }
  }
  function keep(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
  }

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

  // For async views: returns a show() that does nothing if the user navigated away meanwhile.
  function shower() {
    const g = routeGen;
    return (...nodes) => { if (g === routeGen) show(...nodes); };
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

  // any: also accept platform authenticators and passkey providers (iCloud Keychain, 1Password).
  // Used by the self test, and by enrollment only when the user opts into a synced passkey slot.
  // Enrollment credentials are discoverable (resident), so config.json never has to list them.
  async function createCredential(label, excludeSlots, any) {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { id: rpId, name: 'tapseal' },
        user: { id: C.rand(16), name: 'tapseal-' + label, displayName: 'tapseal ' + label },
        challenge: C.rand(32),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: any
          ? { residentKey: 'required', requireResidentKey: true, userVerification: 'required' }
          : { authenticatorAttachment: 'cross-platform', residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
        excludeCredentials: (excludeSlots || []).map((s) => (s.synced ? { type: 'public-key', id: C.b64d(s.credId) }
          : { type: 'public-key', id: C.b64d(s.credId), transports: TRANSPORTS })),
        hints: any ? [] : ['security-key'],
        extensions: { prf: {} },
        timeout: 120000,
      },
    });
    const prf = cred.getClientExtensionResults().prf;
    if (prf && prf.enabled === false) throw new Error('This authenticator or browser does not support PRF.');
    // Synced if the authenticator says the credential can be backed up (BE flag, bit 3 of the
    // flags byte), or it arrived over hybrid (a phone over QR/Bluetooth) or from the platform.
    // A YubiKey reports BE = 0 and transports usb/nfc. Unknown counts as synced.
    let synced = true;
    try {
      const ad = new Uint8Array(cred.response.getAuthenticatorData());
      const transports = (cred.response.getTransports && cred.response.getTransports()) || [];
      synced = (ad[32] & 0x08) !== 0 || transports.includes('hybrid') || transports.includes('internal')
        || cred.authenticatorAttachment !== 'cross-platform';
    } catch { /* cannot tell: treat as synced */ }
    return { credId: C.b64e(new Uint8Array(cred.rawId)), attachment: cred.authenticatorAttachment || 'unknown', synced };
  }

  // Evaluates PRF with prf.eval and one salt shared by every slot (PRF output already differs per
  // credential; some providers implement eval but not evalByCredential). An empty allow list
  // means "any credential for this site", which keeps credential IDs out of config.json.
  // Returns { credId, out, second }.
  async function prfEval(allow, salt, secondSalt) {
    const generic = !allow.length || allow.some((s) => s.synced || s.any);
    const a = await navigator.credentials.get({
      publicKey: {
        rpId,
        challenge: C.rand(32),
        allowCredentials: allow.map((s) => (generic ? { type: 'public-key', id: C.b64d(s.credId) }
          : { type: 'public-key', id: C.b64d(s.credId), transports: TRANSPORTS })),
        userVerification: 'required',
        hints: generic ? [] : ['security-key'],
        extensions: { prf: { eval: secondSalt ? { first: C.b64d(salt), second: secondSalt } : { first: C.b64d(salt) } } },
        timeout: 120000,
      },
    });
    const res = (a.getClientExtensionResults().prf || {}).results;
    if (!res || !res.first) throw new Error('No PRF output. This browser or authenticator does not support PRF here.');
    return { credId: C.b64e(new Uint8Array(a.rawId)), out: new Uint8Array(res.first), second: res.second ? new Uint8Array(res.second) : null };
  }

  // Unlock the keyring with whichever enrolled key or passkey answers.
  // Returns { K, slot } where slot is { label, synced } from the sealed metadata.
  async function openKeyring() {
    if (V2) {
      const { credId, out } = await prfEval([], CFG.salt);
      let hit;
      try { hit = await C.findWrap(CFG.wraps, out); } finally { out.fill(0); }
      if (!hit) throw new Error('That key or passkey is not enrolled here.');
      const meta = await C.openMeta(hit.K, CFG.meta);
      const slot = meta.slots.find((x) => x.wrap === hit.index && x.credId === credId) || { label: 'a paper key slot?', synced: false };
      return { K: hit.K, slot, meta };
    }
    // Config v1 (before 0.3): credential IDs and labels were public.
    const { credId, out } = await prfEval(CFG.slots, CFG.salt);
    const slot = CFG.slots.find((x) => x.credId === credId);
    if (!slot) { out.fill(0); throw new Error('Unexpected credential answered.'); }
    let K;
    try { K = await C.unwrapK(slot, out); } finally { out.fill(0); }
    return { K, slot, meta: null };
  }

  async function openWithPaper(secret) {
    if (V2) {
      const hit = await C.findWrap(CFG.wraps, secret);
      if (!hit) throw new Error('Paper key did not match.');
      return hit.K;
    }
    if (!CFG.paper) throw new Error('No paper key is configured.');
    try { return await C.unwrapK(CFG.paper, secret); } catch { throw new Error('Paper key did not match.'); }
  }

  function shuffle(a) {
    for (let i = a.length - 1; i > 0; i--) {
      const j = new Uint32Array(C.rand(4).buffer)[0] % (i + 1);
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  }

  // Config v2: every wrap (keys, paper, dummies) in one padded list; the map is sealed.
  // A new keyring is shuffled from scratch. An edit (layout given) keeps every existing entry in
  // place, byte for byte, and puts each new wrap where a random dummy was, so comparing two
  // published versions shows only that something was added, not which entries are real.
  async function buildConfig(K, salt, page, slots, paperWrap, extra, layout) {
    let entries;
    const freeDummy = () => {
      let free = entries.map((e, j) => (e.kind === 'dummy' ? j : -1)).filter((j) => j >= 0);
      if (!free.length) {
        const start = entries.length;
        for (let k = 0; k < WRAPS_MIN; k++) entries.push({ kind: 'dummy', wrap: C.dummyWrap() });
        free = entries.map((e, j) => (j >= start ? j : -1)).filter((j) => j >= 0);
      }
      return free[new Uint32Array(C.rand(4).buffer)[0] % free.length];
    };
    if (layout) {
      entries = layout.map((e) => ({ ...e }));
      for (const x of slots) {
        let i = entries.findIndex((e) => e.kind === 'slot' && e.credId === x.credId);
        if (i < 0) i = freeDummy();
        entries[i] = { kind: 'slot', x, credId: x.credId, wrap: { iv: x.iv, wrapped: x.wrapped } };
      }
      if (paperWrap) {
        let i = entries.findIndex((e) => e.kind === 'paper');
        if (i < 0) i = freeDummy();
        entries[i] = { kind: 'paper', wrap: paperWrap };
      }
    } else {
      entries = slots.map((x) => ({ kind: 'slot', x, wrap: { iv: x.iv, wrapped: x.wrapped } }));
      if (paperWrap) entries.push({ kind: 'paper', wrap: paperWrap });
      const n = Math.max(WRAPS_MIN, Math.ceil(entries.length / WRAPS_MIN) * WRAPS_MIN);
      while (entries.length < n) entries.push({ kind: 'dummy', wrap: C.dummyWrap() });
      shuffle(entries);
    }
    const meta = { slots: [], paper: null };
    entries.forEach((e, i) => {
      if (e.kind === 'slot') meta.slots.push({ label: e.x.label, credId: e.x.credId, synced: !!e.x.synced, wrap: i });
      else if (e.kind === 'paper') meta.paper = i;
    });
    return { v: 2, rpId, salt, pageKey: page.pageKey, pageSeal: page.pageSeal,
      wraps: entries.map((e) => e.wrap), meta: await C.sealMeta(K, meta), ...(extra || {}) };
  }

  const slotName = (s) => s.label + (s.synced ? ' (synced passkey)' : '');

  // Security key gate yielding K and the page signing key. The paper key is deliberately
  // NOT offered here: links arrive from the agent, and a lookalike page could ask for it.
  // keepK: the callback takes ownership of K (enrollment). Otherwise K is zeroed afterwards.
  function keyGate(label, onOpen, keepK) {
    const tap = el('button', { class: 'primary' }, label);
    tap.addEventListener('click', busy(tap, async () => {
      setStatus('Use an enrolled key or passkey, then verify with PIN, fingerprint, or Face ID.');
      const { K, slot, meta } = await openKeyring();
      try {
        const signer = await C.openPageKey(K, CFG.pageSeal);
        setStatus('Unlocked with ' + slotName(slot) + '.', slot.synced ? 'warn' : 'ok');
        await onOpen(K, signer, slotName(slot), meta);
      } finally { if (!keepK) K.fill(0); }
    }));
    return el('div', { class: 'row' }, tap);
  }

  function needConfig() {
    const ok = CFG && CFG.salt && CFG.pageKey && CFG.pageSeal
      && (V2 ? Array.isArray(CFG.wraps) && CFG.wraps.length && CFG.meta : Array.isArray(CFG.slots) && CFG.slots.length);
    if (ok) return false;
    show(card(el('h2', {}, 'Not enrolled'),
      el('p', {}, 'This page has no keyring yet. Open ', el('a', { href: '#enroll' }, 'Enroll'), ' to set it up.')));
    return true;
  }

  // ---------- views ----------

  async function viewHome() {
    const show = shower();
    const items = [el('h1', {}, 'tapseal')];
    if (CFG && CFG.pageKey) {
      items.push(card(
        el('p', {}, V2 ? 'Enrolled.' : 'Enrolled, in the old format that shows your keys publicly. Open Enroll or add keys to upgrade.'),
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
      el('a', { href: '#rotate' }, 'Rotate vault key'), el('a', { href: '#revoke' }, 'Revoke VM certificates'),
      el('a', { href: '#selftest' }, 'PRF self test'),
      el('a', { href: '#recover' }, 'Recover with paper key')));
    show(...items, status);
  }

  async function viewUnlock(blob, certStr, reqStr) {
    if (needConfig()) return;
    const show = shower();
    let claimed, cert, req;
    try {
      claimed = C.parseVault(blob).claimed;
      if (!certStr || !reqStr) throw new Error('Link is incomplete. Ask the agent for a new link.');
      cert = await C.verifyCert(CFG.pageKey, certStr, null, CFG.minCertIat);
      req = await C.verifyRequest(cert.vmKey, reqStr);
      if (req.name !== claimed.name) throw new Error('Request and secret names differ. Do not unlock.');
    } catch (e) {
      show(el('h1', {}, 'Bad link'), card(el('p', { class: 'bad' }, explain(e))));
      return;
    }

    const fp = await C.fingerprint(cert.vmKey);
    const mine = store(CERTLOG_KEY, []).find((x) => x.fp === fp && x.iat === cert.iat);
    const provenance = mine
      ? el('p', { class: 'muted' }, 'You certified this VM identity from this device ' + ago(cert.iat) + '.')
      : el('p', { class: 'bad' }, 'This VM identity was not certified from this device (it was certified ' + ago(cert.iat)
        + '). If you did not certify it on another device, do not unlock.');
    const body = el('div');
    show(el('h1', {}, 'Unlock request'),
      card(
        el('p', {}, 'Your VM is asking for ', el('strong', {}, String(req.name)), '.'),
        el('p', { class: 'muted' }, 'Request expires ' + until(req.exp) + '. VM identity ',
          el('code', {}, fp), ', certificate valid until ' + new Date(cert.exp * 1000).toLocaleDateString() + '.'),
        provenance,
        keyGate('Unlock with security key', async (K, signer) => {
          const sec = await C.unseal(K, blob);
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
    const show = shower();
    let fp;
    try { const raw = C.b64d(vmKey); if (raw.length !== 65 || raw[0] !== 4) throw new Error(); fp = await C.fingerprint(vmKey); }
    catch { show(el('h1', {}, 'Bad link'), card(el('p', { class: 'bad' }, 'Not a VM identity key.'))); return; }
    const life = el('select', {}, [[1, '1 day'], [7, '7 days'], [30, '30 days']].map(([d, t]) =>
      el('option', { value: d * 86400, selected: d === 7 }, t)));
    const log = store(CERTLOG_KEY, []);
    const last = log[log.length - 1];
    const recent = last && last.fp !== fp && C.now() - last.iat < 86400
      ? warn(el('p', {}, 'You certified a different VM identity ' + ago(last.iat) + ' from this device. '
        + 'Agents restart, but two certify requests in a day deserve a second look.')) : null;
    const out = el('div');
    show(el('h1', {}, 'Certify VM identity'),
      warn(el('p', {}, 'Certify only if your agent just started or restarted and asked for this in your usual chat, at a time you expect. '
        + 'Whoever you certify can send you unlock requests that look like they come from your VM.'),
        el('p', { class: 'muted' }, 'This page cannot verify who sent the link: the fingerprint below comes from the link itself. '
          + 'Your judgment about the request is the check.'),
        el('p', {}, 'Identity fingerprint: ', el('code', {}, fp))),
      recent,
      card(el('label', {}, 'Valid for ', life),
        keyGate('Certify with security key', async (K, signer) => {
          const cert = await C.certify(signer, CFG.pageKey, vmKey, Number(life.value));
          const h = JSON.parse(new TextDecoder().decode(C.b64d(cert.split('.')[1])));
          keep(CERTLOG_KEY, [...store(CERTLOG_KEY, []), { fp, iat: h.iat, exp: h.exp }].slice(-50));
          out.replaceChildren(output('Paste this into chat', cert,
            'The agent runs: tapseal certify. Contains no secrets.'));
        })),
      out, status);
  }

  // Revoke every VM certificate issued before now, without rotating: one config.json commit.
  function viewRevoke() {
    if (needConfig()) return;
    const go = el('button', { class: 'primary' }, 'Generate config.json');
    const out = el('div');
    go.addEventListener('click', () => {
      const cfg = { ...CFG, minCertIat: C.now() };
      out.replaceChildren(output('config.json', JSON.stringify(cfg, null, 2) + '\n',
        'Commit this to your deploy repo. Once deployed, every existing VM certificate is refused, and each agent must ask you to certify it again.'));
    });
    show(el('h1', {}, 'Revoke VM certificates'),
      card(el('p', {}, 'Use this if you certified something you should not have, or a device with your chat history was lost. '
        + 'It needs no key: the commit is the act.'), el('div', { class: 'row' }, go)),
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
          {
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
          }
        })),
      out, status);
  }

  // Key management.
  //   'new'    fresh keyring
  //   'add'    unlock with a key, add more keys (same vault key). On a v1 config this is the
  //            upgrade to v2: every key is registered again as discoverable, nothing else changes.
  //   'rotate' new vault key and page key; old keys, old paper key, and old configs stop working
  // gate: 'key' or 'paper' (how to open the current keyring for 'add' and 'rotate')
  function viewEnroll(mode, gate) {
    if (location.hostname.endsWith('.github.io')) {
      show(el('h1', {}, 'Use your own domain'),
        warn(el('p', {}, 'Enrolling on ' + location.hostname + ' would bind your keys to an origin every GitHub Pages site on this account shares. '
          + 'Any of them could use your keys. Set up a custom subdomain first (docs/SETUP.md).')));
      return;
    }
    if (mode !== 'new' && needConfig()) return;
    const upgrade = mode === 'add' && !V2;
    let K = null, oldK = null, oldSigner = null, page = null;
    let slots = [];   // { label, credId, synced?, iv, wrapped }
    const salt = mode === 'add' ? CFG.salt : C.b64e(C.rand(32));
    // An upgrade issues a new paper key: the old paper wrap is public in the v1 config's history,
    // so carrying it over would mark which entry is the paper key.
    let paperSlot = null;
    let layout = null;
    let paperShown = null;

    const list = el('ul');
    const renderList = () => list.replaceChildren(...slots.map((s) => el('li', {}, slotName(s))));
    renderList();

    const label = input({ placeholder: 'e.g. yk-nfc, yk-bio' });
    const kindSel = el('select', {}, el('option', { value: 'hardware', selected: true }, 'Hardware security key (recommended)'),
      el('option', { value: 'synced' }, 'Synced passkey (iCloud Keychain, 1Password)'));
    const kindWarn = warn(el('p', {}, 'A synced passkey opens the whole vault on its own. Anyone with that passkey account '
      + '(Apple ID or 1Password), or an unlocked device that has the passkey, gets every secret. '
      + 'Your hardware keys do not make up for it: any one slot is enough.'));
    kindWarn.classList.add('hidden');
    kindSel.addEventListener('change', () => kindWarn.classList.toggle('hidden', kindSel.value !== 'synced'));
    const add = el('button', { class: 'primary' }, 'Register key');
    add.addEventListener('click', busy(add, async () => {
      const l = label.value.trim();
      if (!/^[\w-]{1,32}$/.test(l)) throw new Error('Give the key a short label.');
      if (slots.some((s) => s.label === l)) throw new Error('Label already used.');
      const wantSynced = kindSel.value === 'synced';
      setStatus('Step 1 of 2: register it.');
      const { credId, synced } = await createCredential(l, slots, wantSynced);
      const slot = { label: l, credId };
      if (synced) {
        if (!wantSynced) throw new Error('That was not a hardware security key (it can be synced or backed up). Choose "Synced passkey" to allow it.');
        slot.synced = true;
      }
      setStatus('Step 2 of 2: derive its secret.');
      const { out } = await prfEval([{ credId, synced: slot.synced, any: wantSynced }], salt);
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
    const gen = el('button', { class: 'primary' }, 'Generate config.json');
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
      let carried = { blobs: [], skipped: [] };
      if (mode === 'rotate' && bundleIn.value.trim()) carried = await C.reseal(oldK, K, bundleIn.value);
      await ensurePaper();
      if (paperShown && !wrote.checked) throw new Error('Confirm you wrote down the paper key.');
      const extra = CFG && CFG.minCertIat && mode !== 'rotate' ? { minCertIat: CFG.minCertIat } : null;
      const cfg = await buildConfig(K, salt, page, slots, paperSlot, extra, layout);
      const outs = [output('config.json', JSON.stringify(cfg, null, 2) + '\n',
        'Replace site/config.json in your deploy repo with this and commit. It reveals no labels, key count, or credential IDs.'
        + (slots.length < 2 ? ' Warning: only one key enrolled.' : ''))];
      if (mode === 'rotate') {
        const pkg = await C.handoff(oldSigner, CFG.pageKey, page.pageKey, carried.blobs);
        outs.push(output('Rotation package for the agent', pkg, 'After committing config.json, send this to the agent: it runs '
          + 'tapseal rotate, then sends you a certify link. Signed by your old page key, so only you could have made it. '
          + 'Carries ' + carried.blobs.length + ' re-sealed secret(s).'));
        if (carried.skipped.length) {
          outs.push(warn(el('p', {}, 'Skipped because they did not open under your old vault key (planted, or from an older keyring): '
            + carried.skipped.join(', '))));
        }
        if (!bundleIn.value.trim()) outs.push(warn(el('p', {}, 'No bundle pasted: secrets sealed under the old vault key will not open with the new one.')));
        outs.push(warn(el('p', {}, 'Old blobs survive in the VM\'s backups and still open with the old vault key. '
          + 'If a key or paper key may be in someone else\'s hands, re-issue the underlying secrets too.')));
      }
      out.replaceChildren(...outs);
    }));

    const setup = el('div', { class: 'hidden' },
      card(el('h2', {}, 'Keys'), list,
        el('p', { class: 'muted' }, mode === 'rotate'
          ? 'Register every key you still have, again. Keys you do not register here stop working.'
          : upgrade ? 'Upgrading: register every key you use again, including passkeys, and write down the new paper key. '
            + 'Your vault key and sealed secrets stay the same. The old paper key still opens copies of your old config, so keep it safe or destroy it.'
          : 'Each key takes two touches.'),
        el('label', {}, 'Type ', kindSel), kindWarn,
        el('div', { class: 'row' }, label, add)),
      mode === 'rotate' ? card(el('h2', {}, 'Secrets to carry over'),
        el('p', { class: 'muted' }, 'Ask the agent for: tapseal export. Paste the tsb1 string here.'), bundleIn) : null,
      card(el('div', { class: 'row' }, gen)),
      paperBox, out);

    let start;
    const begin = async (k, meta) => {
      if (mode === 'new') {
        K = C.rand(32);
      } else if (mode === 'add') {
        K = k;
        if (V2) {
          meta = meta || await C.openMeta(K, CFG.meta);
          slots = meta.slots.map((x) => ({ label: x.label, credId: x.credId, synced: x.synced || undefined, ...CFG.wraps[x.wrap] }));
          paperSlot = meta.paper == null ? null : CFG.wraps[meta.paper];
          layout = CFG.wraps.map((wrap) => ({ kind: 'dummy', wrap }));
          meta.slots.forEach((x) => { layout[x.wrap] = { kind: 'slot', credId: x.credId, wrap: CFG.wraps[x.wrap] }; });
          if (meta.paper != null) layout[meta.paper] = { kind: 'paper', wrap: CFG.wraps[meta.paper] };
          renderList();
        }
      } else {
        oldK = k;
        oldSigner = await C.openPageKey(oldK, CFG.pageSeal);
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
        let secret;
        try { secret = C.paperDecode(paperIn.value); } catch { throw new Error('Paper key did not match.'); }
        const k = await openWithPaper(secret);
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
        mode === 'rotate' ? el('p', {}, 'Makes a new vault key and page key. Your old keys, old paper key, and every old config stop working.') : null,
        upgrade ? el('p', {}, 'Your config is in the old format, which shows your key labels and credential IDs publicly. '
          + 'Unlock, then register your keys again to upgrade.') : null,
        keyGate('Unlock with an enrolled key', async (k, signer, name, meta) => begin(k, meta), true),
        el('p', { class: 'muted' }, 'Lost your keys? ', el('a', { href: '#recover' }, 'Recover with the paper key'), '.'));
    }

    const titles = { new: 'Enroll', add: upgrade ? 'Upgrade keyring' : 'Add keys', rotate: gate === 'paper' ? 'Recover' : 'Rotate vault key' };
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
      const { credId, synced } = await step('Step 1 of 4: create a throwaway discoverable credential. On a security key it uses one resident slot; delete it later in your key\'s app if you like.',
        () => createCredential('selftest', [], true));
      say('Authenticator: ' + (synced ? 'synced passkey (backed up, or from a phone or passkey provider)' : 'hardware security key'));
      const slot = { credId, any: true };
      const salt = C.b64e(C.rand(32));
      const a = await step('Step 2 of 4: sign in without naming the credential, as unlocking does. If asked to choose, pick the tapseal selftest one.',
        () => prfEval([], salt));
      if (a.credId !== credId) throw new Error('A different credential answered. Run the test again and pick the selftest one.');
      const b = await step('Step 3 of 4: sign in again naming it, with the same salt.', () => prfEval([slot], salt));
      const same = C.b64e(a.out) === C.b64e(b.out);
      say(same ? 'PRF is stable across sign ins.' : 'PRF output changed between sign ins.', same ? 'ok' : 'bad');
      say(same ? 'PASS: this device and authenticator support what tapseal needs.' : 'FAIL', same ? 'ok' : 'bad');
      if (same && synced) {
        say('This is a synced passkey. Enrollment accepts it only if you choose "Synced passkey", which lets it open the whole vault.', 'muted');
      }
      if (!same) return;
      say('Step 4 of 4 (optional, tapseal does not need it): evaluate two salts at once.');
      try {
        const c = await prfEval([slot], salt, C.rand(32));
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
        + 'Accepts any passkey or security key, so you can check PRF support; enrollment uses hardware keys unless you opt into a synced passkey slot.'),
        el('div', { class: 'row' }, run), log),
      status);
  }

  function route() {
    routeGen++;
    setStatus('');
    const h = location.hash.slice(1);
    if (h.startsWith('u=')) {
      const q = new URLSearchParams(h);
      return viewUnlock(q.get('u'), q.get('c'), q.get('r'));
    }
    if (h.startsWith('certify=')) return viewCertify(h.slice('certify='.length));
    if (h === 'seal') return viewSeal();
    if (h === 'enroll') return viewEnroll(CFG && CFG.pageKey ? 'add' : 'new', 'key');
    if (h === 'rotate') return viewEnroll('rotate', 'key');
    if (h === 'recover') return viewEnroll('rotate', 'paper');
    if (h === 'selftest') return viewSelftest();
    if (h === 'revoke') return viewRevoke();
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
