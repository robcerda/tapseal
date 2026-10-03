"""Page crypto (Node WebCrypto, site/core.js) <-> VM side (Python, tapseal.core).

Run: python3 -m unittest tests/test_interop.py   (needs node and `cryptography`)
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tapseal import core  # noqa: E402


class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.dir = t
        os.environ.update(TAPSEAL_HOME=str(t / "home"), TAPSEAL_SHM=str(t / "shm"),
                          TAPSEAL_URL="https://unlock.example.com/")
        cls.pub = core.init()
        reqs = {k: core.make_request(n) for k, n in [("oura", "oura"), ("wrapped", "oura"), ("expired", "oura"),
                                                     ("far", "oura"), ("google", "google-agent"), ("tamper", "oura")]}
        # A second VM identity, to prove requests are pinned to ours.
        os.environ["TAPSEAL_HOME"] = str(t / "other")
        reqs["otherIdentity"] = core.init()
        os.environ["TAPSEAL_HOME"] = str(t / "home")
        (t / "requests.json").write_text(json.dumps(reqs))
        r = subprocess.run(["node", str(ROOT / "tests/core.test.js"), cls.pub, str(t)], capture_output=True, text=True)
        print(r.stdout, end="")
        if r.returncode:
            raise AssertionError("node side failed:\n" + r.stdout + r.stderr)
        cls.node_fp = r.stdout.strip().splitlines()[-1].split()[-1]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, f):
        return (self.dir / f).read_text()

    def shm(self, name=""):
        return Path(os.environ["TAPSEAL_SHM"]) / name

    def test_fingerprint_matches_page(self):
        self.assertEqual(core.fingerprint(core.b64d(self.pub)), self.node_fp)

    def test_receive_good_then_replay_refused(self):
        name, exp = core.receive(self.read("good.tsd"))
        self.assertEqual(name, "oura")
        self.assertEqual(self.shm("oura").read_text(), '{"session":"s3cret"}')
        self.assertEqual(stat.S_IMODE(self.shm("oura").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.shm().stat().st_mode), 0o700)
        self.assertAlmostEqual(self.shm("oura").stat().st_mtime, exp, delta=1)
        with self.assertRaisesRegex(core.TapsealError, "no open request"):
            core.receive(self.read("good.tsd"))
        core.lock("oura")
        self.assertFalse(self.shm("oura").exists())

    def test_forward_secrecy_disk_and_logs_are_not_enough(self):
        # Attacker has the identity key from disk and the delivery from chat logs,
        # after the request key was consumed. Nothing on the VM can open it.
        tsd = self.read("google.tsd")
        core.receive(tsd)
        leftovers = list((self.shm(".requests")).glob("*.json"))
        rids = [json.loads(core.b64d(tsd.split(".")[1]))["rid"]]
        self.assertFalse(any(p.stem in rids for p in leftovers))
        self.assertNotIn("LONG-LIVED", self.shm("google-agent").read_text())

    def test_whitespace_wrapped_paste(self):
        core.receive(self.read("wrapped.tsd"))

    def test_expired_and_far_deliveries_refused(self):
        with self.assertRaisesRegex(core.TapsealError, "already expired"):
            core.receive(self.read("expired.tsd"))
        with self.assertRaisesRegex(core.TapsealError, "too far"):
            core.receive(self.read("far.tsd"))

    def test_tampered_header_refused(self):
        with self.assertRaisesRegex(core.TapsealError, "did not open"):
            core.receive(self.read("tampered.tsd"))

    def test_garbage_is_a_clean_error(self):
        for junk in ["", "tsd1.!!!.a.b.c", "tsd1.e30.a.b.c", "hello"]:
            with self.assertRaises(core.TapsealError):
                core.receive(junk)

    def test_store_and_link(self):
        self.assertEqual(core.store(self.read("vault.tsv")), "oura")
        url = core.link("oura")
        self.assertTrue(url.startswith("https://unlock.example.com/#u=tsv1."))
        self.assertIn("&r=tsr1.", url)

    def test_sweep_removes_expired_secret_and_request(self):
        core.make_request("sweepme", ttl=60)
        reqs = list(self.shm(".requests").glob("*.json"))
        self.assertTrue(reqs)
        self.shm().mkdir(exist_ok=True)
        f = self.shm("stale")
        f.write_text("x")
        os.utime(f, (1, 1))
        for p in reqs:
            if json.loads(p.read_text())["name"] == "sweepme":
                os.utime(p, (1, 1))
        gone = core.sweep()
        self.assertIn("stale", gone)
        self.assertTrue(any(g.startswith("request ") for g in gone))
        self.assertFalse(f.exists())

    def test_cli_receive_via_stdin(self):
        req = core.make_request("cli")
        node = (f"require('{ROOT}/site/core.js');"
                f"TAPSEAL.verifyRequest('{self.pub}', '{req}').then(r => "
                "TAPSEAL.deliver(r, {name:'cli', kind:'file', exp: TAPSEAL.now()+120, payload:'p'})).then(console.log)")
        tsd = subprocess.run(["node", "-e", node], capture_output=True, text=True, check=True).stdout
        r = subprocess.run([sys.executable, "-m", "tapseal", "receive"], input=tsd, capture_output=True, text=True,
                           cwd=ROOT, env=os.environ)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cli live until", r.stdout)


if __name__ == "__main__":
    unittest.main()
