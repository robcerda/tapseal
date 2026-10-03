/* tapseal core: pure WebCrypto, no DOM. Loaded by the page and by the tests.
 * Normative description: docs/SPEC.md.
 *
 * Keyring:  random 32-byte vault key K, wrapped once per slot.
 *           slot KEK = HKDF(PRF output | paper key, info "tapseal-v1 keyring")
 * Vault:    tsv1.<b64 header>.<b64 iv>.<b64 ct>
 *           AES-256-GCM under HKDF(K, "tapseal-v1 vault"); AAD = "tsv1.<b64 header>"
 * Request:  tsr1.<b64 header>.<b64 sig>
 *           Issued by the VM per unlock. Header carries a fresh ephemeral ECDH key;
 *           signed (ECDSA P-256) by the VM identity key pinned in config.js.
 * Delivery: tsd1.<b64 header>.<b64 epk>.<b64 iv>.<b64 ct>
 *           ECDH P-256 (page ephemeral -> request ephemeral), HKDF salt = epk || request epk,
 *           info "tapseal-v1 delivery"; AAD = "tsd1.<b64 header>"
 *           The VM deletes the request key once it opens the delivery, so a delivery
 *           copied from chat logs cannot be opened later, even with the VM's disk.
 */
(function (g) {
  'use strict';
  const subtle = g.crypto.subtle;
  const te = new TextEncoder();
  const td = new TextDecoder();
  const NAME_RE = /^[a-z0-9_-]{1,64}$/;
  const RID_RE = /^[A-Za-z0-9_-]{22}$/;

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
  const jsonPart = (s) => JSON.parse(td.decode(b64d(s)));
  const jsonEnc = (o) => b64e(te.encode(JSON.stringify(o)));

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

  // ---------- keyring ----------

  const KR = te.encode('tapseal-v1 keyring');

  async function wrapK(K, secret) {
    const { iv, ct } = await gcmEnc(await aesKey(secret, 'tapseal-v1 keyring'), K, KR);
    return { iv: b64e(iv), wrapped: b64e(ct) };
  }

  async function unwrapK(slot, secret) {
    return gcmDec(await aesKey(secret, 'tapseal-v1 keyring'), b64d(slot.iv), b64d(slot.wrapped), KR);
  }

  // ---------- vault blobs ----------

  async function seal(K, { name, kind, ttl, fmt, data }) {
    if (!NAME_RE.test(name)) throw new Error('Name must be a-z, 0-9, _ or -, max 64.');
    if (kind !== 'file' && kind !== 'google') throw new Error('Unknown kind ' + kind);
    const header = { v: 1, name, kind, created: now() };
    if (kind === 'file') header.ttl = ttl;
    if (kind === 'google') header.fmt = fmt || 'google-auth';
    const h = jsonEnc(header);
    const { iv, ct } = await gcmEnc(await aesKey(K, 'tapseal-v1 vault'), te.encode(data), te.encode('tsv1.' + h));
    return `tsv1.${h}.${b64e(iv)}.${b64e(ct)}`;
  }

  // Header is UNVERIFIED until unseal succeeds.
  function parseVault(blob) {
    const p = String(blob).replace(/\s+/g, '').split('.');
    if (p.length !== 4 || p[0] !== 'tsv1') throw new Error('Not a tsv1 vault blob.');
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

  // ---------- unlock requests (issued and signed by the VM) ----------

  async function importIdentity(b64) {
    const raw = p256Raw(b64, 'VM identity key');
    return subtle.importKey('raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  }

  // Returns the request header only if the pinned VM identity signed it and it has not expired.
  async function verifyRequest(identityB64, req, at) {
    const p = String(req).replace(/\s+/g, '').split('.');
    if (p.length !== 3 || p[0] !== 'tsr1') throw new Error('Not a tsr1 unlock request.');
    const key = await importIdentity(identityB64);
    const good = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64d(p[2]), te.encode('tsr1.' + p[1]));
    if (!good) throw new Error('This link was not issued by your VM. Do not unlock it.');
    const h = jsonPart(p[1]);
    if (h.v !== 1 || !NAME_RE.test(h.name) || !RID_RE.test(h.rid) || !Number.isInteger(h.exp)) {
      throw new Error('Malformed unlock request.');
    }
    p256Raw(h.epk, 'Request key');
    if (h.exp <= (at || now())) throw new Error('This unlock request expired. Ask the agent for a new link.');
    return h;
  }

  // ---------- delivery to the VM ----------

  async function deliver(request, { name, kind, exp, payload }) {
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
    return `tsd1.${h}.${b64e(epk)}.${b64e(iv)}.${b64e(ct)}`;
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
    const exp = now() + Math.max(60, (j.expires_in || 3600) - 60);
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
    NAME_RE, b64e, b64d, rand, now,
    wrapK, unwrapK, seal, parseVault, unseal,
    importIdentity, verifyRequest, deliver, fingerprint,
    mintGoogle, googlePayload, paperEncode, paperDecode,
  };
})(globalThis);
