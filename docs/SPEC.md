# tapseal formats, v1

Normative. The reference implementations are `site/core.js` (page) and
`tapseal/core.py` (VM). A conforming implementation interoperates with both.

## Conventions

- `b64(x)`: base64url without padding (RFC 4648 §5). Decoders ignore
  whitespace, since chat apps wrap long strings.
- `json(o)`: UTF-8 JSON. Implementations must authenticate the exact
  base64url text they received, never a re-serialization.
- `HKDF(ikm, info, salt)`: HKDF-SHA-256, 32-byte output, empty salt unless given.
- `GCM(k, iv, pt, aad)`: AES-256-GCM, 12-byte random IV, 16-byte tag appended to
  the ciphertext.
- P-256 public keys are uncompressed SEC1 points (65 bytes, leading `0x04`).
- Names match `^[a-z0-9_-]{1,64}$`. Request ids match `^[A-Za-z0-9_-]{22}$`
  (16 random bytes).
- Times are integer Unix seconds.

## Keys

| Key | Where | Purpose |
|---|---|---|
| Vault key `K`, 32 random bytes | nowhere at rest; wrapped per slot in `config.js` | seals vault blobs |
| Slot secret | PRF output of an enrolled credential, or the paper key | unwraps `K` |
| VM identity, ECDSA P-256 | VM disk | signs unlock requests; public half pinned in `config.js` as `vmKey` |
| Request key, ECDH P-256 | VM tmpfs, one per request | receives one delivery, then deleted |

## Keyring (config.js)

```
window.TAPSEAL_CONFIG = {
  v: 1, rpId, vmKey: b64(identity public point),
  slots: [{ label, credId: b64, salt: b64(32 random bytes), iv: b64, wrapped: b64 }],
  paper: { iv, wrapped } | null
}
```

- Slot secret: the WebAuthn PRF extension output `results.first` for
  `credId`, evaluated with `salt`. User verification is required.
- Paper key: 32 random bytes, shown as RFC 4648 base32 (52 chars) in groups of 4.
- Wrapping: `kek = HKDF(secret, "tapseal-v1 keyring")`,
  `wrapped = GCM(kek, iv, K, aad = "tapseal-v1 keyring")`.

`config.js` holds no secrets. It is public-safe: every unwrapping secret has
256 bits of entropy and lives in hardware or on paper.

## Vault blob: `tsv1`

```
tsv1.<h>.<b64 iv>.<b64 ct>
h  = b64(json({ v: 1, name, kind: "file"|"google", created, ttl? , fmt? }))
ct = GCM(HKDF(K, "tapseal-v1 vault"), iv, secret, aad = "tsv1." + h)
```

- `file`: `ttl` is the longest delivery lifetime allowed, in seconds.
- `google`: the secret is JSON `{client_id, client_secret?, refresh_token,
  scopes?, token_uri?}`; `fmt` is `google-auth` or `oauth2-go`.

The header is bound as AAD. Renaming a blob or raising its `ttl` fails
authentication. The VM can read the claimed header but cannot verify it.

## Unlock request: `tsr1`

Created by the VM for each unlock.

```
tsr1.<h>.<b64 sig>
h   = b64(json({ v: 1, rid, name, epk: b64(request public point), exp }))
sig = ECDSA-P256-SHA256(identity, "tsr1." + h), IEEE P1363 (r || s, 64 bytes)
```

The VM stores the request's private key in tmpfs with `name` and `exp`. It
deletes the key when a delivery for `rid` opens, or at `exp`.

The page must refuse to proceed unless:
1. `sig` verifies under the pinned `vmKey`;
2. `exp` is in the future;
3. `name` equals the verified vault blob's `name` after unseal.

## Unlock link

```
<page URL>#u=<tsv1 blob>&r=<tsr1 request>
```

Everything rides in the fragment, which browsers do not send to the server.

## Delivery: `tsd1`

```
tsd1.<h>.<b64 epk>.<b64 iv>.<b64 ct>
h      = b64(json({ v: 1, rid, name, kind, exp }))
shared = ECDH(page ephemeral private, request public point)        // 32 bytes
k      = HKDF(shared, "tapseal-v1 delivery", salt = epk || request public point)
ct     = GCM(k, iv, payload, aad = "tsd1." + h)
```

- `exp` is when the VM must delete the payload. The page caps it at the blob's
  `ttl` (`file`) or the access token's lifetime minus 60s (`google`).
- For `google`, the payload is a freshly minted access token in the `fmt`
  shape. The refresh token never leaves the page.

The VM must:
1. Find the request key for `rid`; refuse if there is none or it has expired.
2. Open `ct`. After this, the header is authenticated.
3. Refuse unless `v == 1`, `name` equals the request's `name`, and
   `now < exp <= now + 7 days`.
4. Write the payload to tmpfs at `<shm>/<name>` with mode 0600 and
   mtime = `exp`, then delete the request key.

## Forward secrecy

The identity key only signs. Every delivery is encrypted to a request key that
exists only in tmpfs and is deleted on use or expiry. Holding the VM's disk,
backups, chat history, and agent logs does not open any past delivery. Root
on the live VM while a request is open can open that request's delivery.
