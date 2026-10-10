/* tapseal core: pure WebCrypto, no DOM. Loaded by the page and by the tests.
 * Normative description: docs/SPEC.md.
 *
 * Keyring:  random 32 byte vault key K, wrapped once per slot.
 * Page key: ECDSA P-256 key pair made at enrollment. Private half sealed under K in
 *           config.js; public half in config.js and pinned on the VM. Signs VM
 *           identity certificates and every delivery.
 * Vault:    tsv1.<h>.<iv>.<ct>        AES-256-GCM under HKDF(K, "tapseal-v1 vault")
 * Cert:     tsc1.<h>.<sig>            page key vouches for a VM identity key (kept in VM RAM)
 * Request:  tsr1.<h>.<sig>            VM identity signs a one time ECDH key, valid 15 minutes
 * Delivery: tsd1.<h>.<epk>.<iv>.<ct>.<sig>   ECDH to the request key, signed by the page key
 * Bundle:   tsb1.<b64 json [tsv1...]> all blobs, exported by the VM for a rotation
 * Handoff:  tsk1.<h>.<sig>            rotation package signed by the OLD page key: new page key
 *                                     and re-sealed blobs. The VM repins only with this.
 */
(function (g) {
  'use strict';
  const subtle = g.crypto.subtle;
  const te = new TextEncoder();
  const td = new TextDecoder();
  const NAME_RE = /^[a-z0-9_-]{1,64}$/;
  const RID_RE = /^[A-Za-z0-9_-]{22}$/;
  const REQUEST_MAX = 900;          // seconds a request may live
  const CERT_MAX = 30 * 86400;      // seconds a VM identity certificate may live
  const SKEW = 120;                 // tolerated clock difference between device and VM
  const ECDSA = { name: 'ECDSA', hash: 'SHA-256' };
  const P256 = { name: 'ECDSA', namedCurve: 'P-256' };

  function b64e(u8) {
    if (u8 instanceof ArrayBuffer) u8 = new Uint8Array(u8);
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return g.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64d(s) {
    s = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = g.atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const rand = (n) => g.crypto.getRandomValues(new Uint8Array(n));
  const now = () => Math.floor(Date.now() / 1000);
  const jsonEnc = (o) => b64e(te.encode(JSON.stringify(o)));
  function jsonPart(s) {
    const v = JSON.parse(td.decode(b64d(s)));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Malformed header.');
    return v;
  }
  const parts = (s, prefix, n, what) => {
    const p = String(s).replace(/\s+/g, '').split('.');
    if (p.length !== n || p[0] !== prefix) throw new Error('Not a ' + what + '.');
    return p;
  };

  async function aesKey(ikm, info, salt) {
    const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: salt || new Uint8Array(0), info: te.encode(info) },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }

  async function gcmEnc(key, pt, aad) {
    const iv = rand(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt);
    return { iv, ct: new Uint8Array(ct) };
  }

  async function gcmDec(key, iv, ct, aad) {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));
  }

  function p256Raw(b64, what) {
    const raw = b64d(b64);
    if (raw.length !== 65 || raw[0] !== 4) throw new Error(what + ' must be an uncompressed P-256 point.');
    return raw;
  }

  const importVerify = (b64, what) => subtle.importKey('raw', p256Raw(b64, what), P256, false, ['verify']);

  async function verifySig(pubB64, what, sigB64, msg) {
    const sig = b64d(sigB64);
    if (sig.length !== 64) return false;
    return subtle.verify(ECDSA, await importVerify(pubB64, what), sig, te.encode(msg));
  }

  // ---------- keyring ----------

  const KR = te.encode('tapseal-v1 keyring');

  async function wrapK(K, secret) {
    const { iv, ct } = await gcmEnc(await aesKey(secret, 'tapseal-v1 keyring'), K, KR);
    return { iv: b64e(iv), wrapped: b64e(ct) };
  }

  async function unwrapK(slot, secret) {
    return gcmDec(await aesKey(secret, 'tapseal-v1 keyring'), b64d(slot.iv), b64d(slot.wrapped), KR);
  }

  // ---------- page signing key ----------

  const PK = te.encode('tapseal-v1 page key');

  async function newPageKey(K) {
    const kp = await subtle.generateKey(P256, true, ['sign', 'verify']);
    const pub = b64e(await subtle.exportKey('raw', kp.publicKey));
    const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
    const { iv, ct } = await gcmEnc(await aesKey(K, 'tapseal-v1 page key'), pkcs8, PK);
    pkcs8.fill(0);
    return { pageKey: pub, pageSeal: { iv: b64e(iv), sealed: b64e(ct) } };
  }

  // Returns a non-extractable signing key. Fails unless K is the vault key of this config.
  async function openPageKey(K, pageSeal) {
    const pkcs8 = await gcmDec(await aesKey(K, 'tapseal-v1 page key'), b64d(pageSeal.iv), b64d(pageSeal.sealed), PK);
    try { return await subtle.importKey('pkcs8', pkcs8, P256, false, ['sign']); } finally { pkcs8.fill(0); }
  }

  const sign = async (priv, msg) => b64e(await subtle.sign(ECDSA, priv, te.encode(msg)));

  // ---------- vault blobs ----------

  async function seal(K, { name, kind, ttl, fmt, data, created }) {
    if (!NAME_RE.test(name)) throw new Error('Name must be a-z, 0-9, _ or -, max 64.');
    if (kind !== 'file' && kind !== 'google') throw new Error('Unknown kind ' + kind);
    const header = { v: 1, name, kind, created: created || now() };
    if (kind === 'file') {
      if (!Number.isInteger(ttl) || ttl < 60 || ttl > 7 * 86400) throw new Error('Bad ttl.');
      header.ttl = ttl;
    }
    if (kind === 'google') header.fmt = fmt || 'google-auth';
    const h = jsonEnc(header);
    const { iv, ct } = await gcmEnc(await aesKey(K, 'tapseal-v1 vault'), te.encode(data), te.encode('tsv1.' + h));
    return `tsv1.${h}.${b64e(iv)}.${b64e(ct)}`;
  }

  // Header is UNVERIFIED until unseal succeeds.
  function parseVault(blob) {
    const p = parts(blob, 'tsv1', 4, 'tsv1 vault blob');
    return { claimed: jsonPart(p[1]), h: p[1], iv: b64d(p[2]), ct: b64d(p[3]) };
  }

  async function unseal(K, blob) {
    const v = parseVault(blob);
    let pt;
    try {
      pt = await gcmDec(await aesKey(K, 'tapseal-v1 vault'), v.iv, v.ct, te.encode('tsv1.' + v.h));
    } catch (e) {
      throw new Error('Blob failed authentication: it was not sealed by your vault, or it was altered.');
    }
    return { header: v.claimed, data: td.decode(pt) };
  }

  // Re-seal every blob in a bundle from oldK to newK, keeping each header. Blobs that do not
  // open under oldK (planted, or from an older keyring) are skipped and reported by claimed name.
  async function reseal(oldK, newK, bundle) {
    const blobs = [], skipped = [];
    for (const blob of parseBundle(bundle)) {
      try {
        const { header, data } = await unseal(oldK, blob);
        blobs.push(await seal(newK, { ...header, data }));
      } catch {
        let name = '?';
        try { name = String(parseVault(blob).claimed.name); } catch { /* unreadable */ }
        skipped.push(name);
      }
    }
    return { blobs, skipped };
  }

  // Rotation handoff, signed by the OLD page key. Carries the new page key and the re-sealed
  // blobs, so a VM can only be repinned, or fed blobs, by whoever holds the old vault key.
  async function handoff(oldSigner, oldPageKey, newPageKey, blobs) {
    const h = jsonEnc({ v: 1, oldPageKey, newPageKey, iat: now(), blobs });
    return `tsk1.${h}.${await sign(oldSigner, 'tsk1.' + h)}`;
  }

  async function verifyHandoff(oldPageKey, s) {
    const p = parts(s, 'tsk1', 3, 'tsk1 handoff');
    if (!(await verifySig(oldPageKey, 'Page key', p[2], 'tsk1.' + p[1]))) throw new Error('Handoff signature is invalid.');
    const h = jsonPart(p[1]);
    if (h.v !== 1 || h.oldPageKey !== oldPageKey || !Array.isArray(h.blobs)) throw new Error('Malformed handoff.');
    p256Raw(h.newPageKey, 'New page key');
    return h;
  }

  function makeBundle(blobs) { return 'tsb1.' + jsonEnc(blobs); }

  function parseBundle(s) {
    const p = parts(s, 'tsb1', 2, 'tsb1 bundle');
    const list = JSON.parse(td.decode(b64d(p[1])));
    if (!Array.isArray(list) || !list.every((x) => typeof x === 'string')) throw new Error('Malformed bundle.');
    return list;
  }

  // ---------- VM identity certificates ----------

  async function certify(pagePriv, pageKey, vmKey, lifetime) {
    p256Raw(vmKey, 'VM identity key');
    if (!Number.isInteger(lifetime) || lifetime < 3600 || lifetime > CERT_MAX) throw new Error('Bad certificate lifetime.');
    const t = now();
    const h = jsonEnc({ v: 1, vmKey, pageKey, iat: t, exp: t + lifetime });
    return `tsc1.${h}.${await sign(pagePriv, 'tsc1.' + h)}`;
  }

  async function verifyCert(pageKey, cert, at, minIat) {
    const p = parts(cert, 'tsc1', 3, 'tsc1 certificate');
    if (!(await verifySig(pageKey, 'Page key', p[2], 'tsc1.' + p[1]))) {
      throw new Error('This link carries a VM identity you never certified. Do not unlock it.');
    }
    const h = jsonPart(p[1]);
    const t = at || now();
    if (h.v !== 1 || h.pageKey !== pageKey || !Number.isInteger(h.exp) || !Number.isInteger(h.iat)) throw new Error('Malformed certificate.');
    if (minIat && h.iat < minIat) throw new Error('This VM identity certificate was revoked. Ask the agent to send a certify link.');
    p256Raw(h.vmKey, 'VM identity key');
    if (h.exp <= t) throw new Error('Your VM identity certificate expired. Ask the agent to send a certify link.');
    if (h.exp > t + CERT_MAX + SKEW || h.exp - h.iat > CERT_MAX) throw new Error('Certificate lifetime is out of range.');
    return h;
  }

  // ---------- unlock requests (issued and signed by the VM identity) ----------

  async function verifyRequest(vmKey, req, at) {
    const p = parts(req, 'tsr1', 3, 'tsr1 unlock request');
    if (!(await verifySig(vmKey, 'VM identity key', p[2], 'tsr1.' + p[1]))) {
      throw new Error('This link was not issued by your VM. Do not unlock it.');
    }
    const h = jsonPart(p[1]);
    const t = at || now();
    if (h.v !== 1 || !NAME_RE.test(h.name) || !RID_RE.test(h.rid) || !Number.isInteger(h.exp)) {
      throw new Error('Malformed unlock request.');
    }
    p256Raw(h.epk, 'Request key');
    if (h.exp <= t) throw new Error('This unlock request expired. Ask the agent for a new link.');
    if (h.exp > t + REQUEST_MAX + SKEW) throw new Error('This unlock request claims too long a lifetime. Do not unlock it.');
    return h;
  }

  // ---------- delivery to the VM ----------

  async function deliver(request, pagePriv, { name, kind, exp, payload }) {
    if (!NAME_RE.test(name)) throw new Error('bad name');
    if (name !== request.name) throw new Error('Delivery name does not match the request.');
    const reqRaw = p256Raw(request.epk, 'Request key');
    const reqKey = await subtle.importKey('raw', reqRaw, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const epk = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: reqKey }, eph.privateKey, 256));
    const salt = new Uint8Array(epk.length + reqRaw.length);
    salt.set(epk, 0);
    salt.set(reqRaw, epk.length);
    const key = await aesKey(shared, 'tapseal-v1 delivery', salt);
    shared.fill(0);
    const h = jsonEnc({ v: 1, rid: request.rid, name, kind, exp });
    const { iv, ct } = await gcmEnc(key, te.encode(payload), te.encode('tsd1.' + h));
    const body = `tsd1.${h}.${b64e(epk)}.${b64e(iv)}.${b64e(ct)}`;
    return `${body}.${await sign(pagePriv, body)}`;
  }

  async function fingerprint(b64) {
    const d = new Uint8Array(await subtle.digest('SHA-256', b64d(b64)));
    return b64e(d.slice(0, 9)); // 12 chars
  }

  // ---------- Google: mint an access token, never deliver the refresh token ----------

  function googlePayload(info, accessToken, exp, fmt) {
    const expiry = new Date(exp * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
    if (fmt === 'oauth2-go') {
      return JSON.stringify({ access_token: accessToken, token_type: 'Bearer', refresh_token: '', expiry });
    }
    // google-auth authorized_user shape; dummy refresh fields make refresh fail cleanly at expiry.
    return JSON.stringify({
      token: accessToken, refresh_token: 'locked', token_uri: info.token_uri || 'https://oauth2.googleapis.com/token',
      client_id: info.client_id, client_secret: 'locked', scopes: info.scopes || [], expiry,
    });
  }

  async function mintGoogle(dataJson, fmt, fetchImpl) {
    const info = JSON.parse(dataJson);
    if (!info.refresh_token || !info.client_id) throw new Error('Sealed Google secret lacks refresh_token or client_id.');
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: info.refresh_token, client_id: info.client_id });
    if (info.client_secret) body.set('client_secret', info.client_secret);
    let r;
    try {
      r = await (fetchImpl || g.fetch)('https://oauth2.googleapis.com/token', { method: 'POST', body });
    } catch (e) {
      throw new Error('Could not reach Google token endpoint (network or CORS). Nothing was delivered.');
    }
    const j = await r.json();
    if (!r.ok || !j.access_token) throw new Error('Google refused the refresh: ' + (j.error_description || j.error || r.status));
    const exp = now() + Math.min(3600, Math.max(60, (j.expires_in || 3600) - 60));
    return { payload: googlePayload(info, j.access_token, exp, fmt), exp };
  }

  // ---------- paper key (RFC 4648 base32, grouped) ----------

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function paperEncode(u8) {
    let bits = 0, val = 0, out = '';
    for (const b of u8) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
      val &= (1 << bits) - 1;
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out.match(/.{1,4}/g).join('-');
  }

  function paperDecode(s) {
    const clean = String(s).toUpperCase().replace(/[^A-Z2-7]/g, '');
    let bits = 0, val = 0;
    const out = [];
    for (const c of clean) {
      val = (val << 5) | B32.indexOf(c); bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
      val &= (1 << bits) - 1;
    }
    if (out.length !== 32) throw new Error('Paper key should be 52 characters.');
    return new Uint8Array(out);
  }

  g.TAPSEAL = {
    NAME_RE, REQUEST_MAX, CERT_MAX, b64e, b64d, rand, now,
    wrapK, unwrapK, newPageKey, openPageKey,
    seal, parseVault, unseal, reseal, makeBundle, parseBundle, handoff, verifyHandoff,
    certify, verifyCert, verifyRequest, deliver, fingerprint,
    mintGoogle, googlePayload, paperEncode, paperDecode,
  };
})(globalThis);
