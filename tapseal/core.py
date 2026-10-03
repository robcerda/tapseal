"""tapseal VM side. Holds a signing identity and short-lived request keys, never a vault key.

The VM stores sealed vault blobs (it cannot open them), issues signed unlock
requests, and opens deliveries the user makes from their phone. Each request
carries a fresh ECDH key kept only in tmpfs and deleted once its delivery is
opened or it expires, so a delivery copied from chat or agent logs cannot be
opened later, even by someone holding the VM's disk.

Formats are specified in docs/SPEC.md.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NAME_RE = re.compile(r"^[a-z0-9_-]{1,64}$")
RID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
MAX_LIFETIME = 7 * 86400
REQUEST_TTL = 900
MAX_REQUEST_TTL = 3600
TMP_GRACE = 60


class TapsealError(Exception):
    pass


@dataclass(frozen=True)
class Paths:
    home: Path
    shm: Path

    @property
    def identity(self) -> Path:
        return self.home / "identity.pem"

    @property
    def vault(self) -> Path:
        return self.home / "vault"

    @property
    def requests(self) -> Path:
        return self.shm / ".requests"


def paths() -> Paths:
    return Paths(
        home=Path(os.environ.get("TAPSEAL_HOME", "~/.config/tapseal")).expanduser(),
        shm=Path(os.environ.get("TAPSEAL_SHM", "/dev/shm/tapseal")),
    )


# ---------- encoding helpers ----------

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise TapsealError("malformed base64") from None


def json_part(s: str) -> dict:
    try:
        v = json.loads(b64d(s))
    except (ValueError, TapsealError):
        raise TapsealError("unreadable header") from None
    if not isinstance(v, dict):
        raise TapsealError("unreadable header")
    return v


def clean(text: str) -> str:
    """Chat apps wrap long strings; whitespace is never meaningful."""
    return re.sub(r"\s+", "", text)


def private_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(p, 0o700)


def write_private(path: Path, data: bytes, mtime: int | None = None) -> None:
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if mtime is not None:
        os.utime(tmp, (time.time(), mtime))
    os.replace(tmp, path)


def raw_point(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def fingerprint(raw: bytes) -> str:
    from hashlib import sha256
    return b64e(sha256(raw).digest()[:9])


# ---------- identity (signing) key ----------

def init(force: bool = False) -> str:
    P = paths()
    if P.identity.exists() and not force:
        raise TapsealError(f"{P.identity} exists; pass --force to replace it (the unlock page must be re-pinned)")
    private_dir(P.home)
    priv = ec.generate_private_key(ec.SECP256R1())
    write_private(P.identity, priv.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    return identity_pub()


def load_identity() -> ec.EllipticCurvePrivateKey:
    P = paths()
    if not P.identity.exists():
        raise TapsealError(f"no identity key at {P.identity}; run: tapseal init")
    return serialization.load_pem_private_key(P.identity.read_bytes(), password=None)


def identity_pub() -> str:
    return b64e(raw_point(load_identity().public_key()))


def sign(priv: ec.EllipticCurvePrivateKey, msg: bytes) -> bytes:
    """ECDSA P-256 / SHA-256 in IEEE P1363 form (r || s), which WebCrypto verifies."""
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ---------- vault blobs (stored, never opened here) ----------

def store(text: str) -> str:
    blob = clean(text)
    p = blob.split(".")
    if len(p) != 4 or p[0] != "tsv1":
        raise TapsealError("not a tsv1 vault blob")
    name = json_part(p[1]).get("name", "")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise TapsealError("bad name in blob")
    P = paths()
    private_dir(P.vault)
    write_private(P.vault / f"{name}.tsv", blob.encode())
    return name


def stored() -> list[str]:
    P = paths()
    if not P.vault.exists():
        return []
    return sorted(p.stem for p in P.vault.glob("*.tsv"))


# ---------- unlock requests ----------

def make_request(name: str, ttl: int = REQUEST_TTL) -> str:
    """Mint a one-shot ECDH key in tmpfs and return the signed tsr1 request for it."""
    if not NAME_RE.match(name):
        raise TapsealError("bad name")
    if not 60 <= ttl <= MAX_REQUEST_TTL:
        raise TapsealError(f"request ttl must be 60..{MAX_REQUEST_TTL} seconds")
    identity = load_identity()
    P = paths()
    private_dir(P.shm)
    private_dir(P.requests)
    eph = ec.generate_private_key(ec.SECP256R1())
    rid = b64e(secrets.token_bytes(16))
    exp = int(time.time()) + ttl
    record = {
        "name": name,
        "exp": exp,
        "key": eph.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()).decode(),
    }
    write_private(P.requests / f"{rid}.json", json.dumps(record).encode(), mtime=exp)
    h = b64e(json.dumps({"v": 1, "rid": rid, "name": name, "epk": b64e(raw_point(eph.public_key())),
                         "exp": exp}, separators=(",", ":")).encode())
    return f"tsr1.{h}.{b64e(sign(identity, f'tsr1.{h}'.encode()))}"


def link(name: str, url: str | None = None, ttl: int = REQUEST_TTL) -> str:
    P = paths()
    if not NAME_RE.match(name):
        raise TapsealError("bad name")
    blob_path = P.vault / f"{name}.tsv"
    if not blob_path.exists():
        raise TapsealError(f"no vault blob for {name}; ask the user to seal it and send the tsv1 string")
    url = url or os.environ.get("TAPSEAL_URL")
    if not url:
        raise TapsealError("set TAPSEAL_URL to the unlock page, e.g. https://unlock.example.com/")
    req = make_request(name, ttl)
    return f"{url.rstrip('/')}/#u={blob_path.read_text().strip()}&r={req}"


# ---------- deliveries ----------

def receive(text: str) -> tuple[str, int]:
    tsd = clean(text)
    p = tsd.split(".")
    if len(p) != 5 or p[0] != "tsd1":
        raise TapsealError("not a tsd1 delivery")
    h = p[1]
    rid = json_part(h).get("rid", "")
    if not isinstance(rid, str) or not RID_RE.match(rid):
        raise TapsealError("bad request id in delivery")

    P = paths()
    req_path = P.requests / f"{rid}.json"
    try:
        req = json.loads(req_path.read_text())
    except FileNotFoundError:
        raise TapsealError("no open request for this delivery: already received, expired, "
                           "or made for another VM. Send a new link.") from None
    now = int(time.time())
    if req["exp"] <= now:
        req_path.unlink(missing_ok=True)
        raise TapsealError("the unlock request expired before delivery. Send a new link.")

    priv = serialization.load_pem_private_key(req["key"].encode(), password=None)
    mine = raw_point(priv.public_key())
    epk_raw, iv, ct = b64d(p[2]), b64d(p[3]), b64d(p[4])
    try:
        epk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_raw)
        shared = priv.exchange(ec.ECDH(), epk)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=epk_raw + mine,
                   info=b"tapseal-v1 delivery").derive(shared)
        payload = AESGCM(key).decrypt(iv, ct, f"tsd1.{h}".encode())
    except Exception:
        raise TapsealError("delivery did not open: corrupted or altered") from None

    header = json_part(h)  # authenticated via AAD from here on
    name, exp = header.get("name", ""), header.get("exp")
    if header.get("v") != 1 or not isinstance(name, str) or name != req["name"] or not isinstance(exp, int):
        raise TapsealError("delivery header does not match its request")
    if exp <= now:
        raise TapsealError(f"{name}: delivery already expired")
    if exp > now + MAX_LIFETIME:
        raise TapsealError(f"{name}: expiry too far out")

    private_dir(P.shm)
    write_private(P.shm / name, payload, mtime=exp)  # mtime = expiry; sweep relies on it
    req_path.unlink(missing_ok=True)  # one-shot: forward secrecy and no replay
    return name, exp


# ---------- live secrets ----------

def live() -> list[tuple[str, float]]:
    P = paths()
    if not P.shm.exists():
        return []
    return sorted((p.name, p.stat().st_mtime) for p in P.shm.iterdir()
                  if p.is_file() and not p.name.endswith(".tmp"))


def lock(name: str | None = None) -> list[str]:
    P = paths()
    if name is not None and not NAME_RE.match(name):
        raise TapsealError("bad name")
    targets = [name] if name else [n for n, _ in live()]
    gone = []
    for n in targets:
        try:
            (P.shm / n).unlink()
            gone.append(n)
        except FileNotFoundError:
            pass
    return gone


def sweep() -> list[str]:
    """Delete expired secrets, expired request keys, and stale temp files."""
    P = paths()
    now = time.time()
    gone = []
    for d in (P.shm, P.requests):
        if not d.exists():
            continue
        for p in d.iterdir():
            try:
                if not p.is_file():
                    continue
                m = p.stat().st_mtime
                if (p.name.endswith(".tmp") and m <= now - TMP_GRACE) or (not p.name.endswith(".tmp") and m <= now):
                    p.unlink()
                    gone.append(p.name if d == P.shm else f"request {p.stem}")
            except FileNotFoundError:
                pass
    return gone
