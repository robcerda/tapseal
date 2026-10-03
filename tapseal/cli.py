"""tapseal: VM side of hardware-key-gated secrets for agents on hosts you don't control.

  tapseal init [--force]       create the VM identity key; print its public key
  tapseal pubkey               print the identity public key and its fingerprint
  tapseal store [BLOB]         save a tsv1 vault blob (arg or stdin) under its name
  tapseal link NAME [--ttl S]  issue a signed one-shot unlock request; print the URL
  tapseal receive [TSD]        open a tsd1 delivery (stdin preferred) into tmpfs
  tapseal status               list live secrets and expiry
  tapseal lock [NAME]          delete live secret(s) now
  tapseal sweep [--loop N]     delete expired secrets and request keys

Env: TAPSEAL_HOME (default ~/.config/tapseal), TAPSEAL_URL (unlock page),
     TAPSEAL_SHM (default /dev/shm/tapseal; must be tmpfs).
"""
from __future__ import annotations

import argparse
import sys
import time

from . import __version__, core


def _stdin_or(val: str | None) -> str:
    return val if val else sys.stdin.read()


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M %Z", time.localtime(ts))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tapseal", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"tapseal {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init"); p.add_argument("--force", action="store_true")
    sub.add_parser("pubkey")
    p = sub.add_parser("store"); p.add_argument("blob", nargs="?")
    p = sub.add_parser("link"); p.add_argument("name"); p.add_argument("--ttl", type=int, default=core.REQUEST_TTL)
    p = sub.add_parser("receive"); p.add_argument("tsd", nargs="?")
    sub.add_parser("status")
    p = sub.add_parser("lock"); p.add_argument("name", nargs="?")
    p = sub.add_parser("sweep"); p.add_argument("--loop", type=int)
    a = ap.parse_args(argv)

    try:
        if a.cmd in ("init", "pubkey"):
            pub = core.init(a.force) if a.cmd == "init" else core.identity_pub()
            print(pub)
            print(f"fingerprint: {core.fingerprint(core.b64d(pub))}", file=sys.stderr)
        elif a.cmd == "store":
            name = core.store(_stdin_or(a.blob))
            print(f"stored {name} (header unverified here; only the user's keys can verify it)")
        elif a.cmd == "link":
            core.sweep()
            print(core.link(a.name, ttl=a.ttl))
        elif a.cmd == "receive":
            core.sweep()
            name, exp = core.receive(_stdin_or(a.tsd))
            print(f"{name} live until {fmt_time(exp)}")
        elif a.cmd == "status":
            core.sweep()
            rows = core.live()
            if not rows:
                print("nothing live (locked)")
            for name, exp in rows:
                print(f"{name:24} {int(exp - time.time()) // 60}m left")
        elif a.cmd == "lock":
            for n in core.lock(a.name):
                print(f"locked {n}")
        elif a.cmd == "sweep":
            while True:
                for n in core.sweep():
                    print(f"{time.strftime('%H:%M:%S')} expired {n}", file=sys.stderr)
                if not a.loop:
                    break
                time.sleep(a.loop)
    except core.TapsealError as e:
        print(f"tapseal: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
