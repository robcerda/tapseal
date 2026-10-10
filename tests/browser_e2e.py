"""Full page flow in Chromium with a virtual PRF authenticator:
selftest -> enroll -> certify -> seal -> store -> link -> unlock -> deliver -> receive,
plus forged links, hostname pinning, and paper recovery that rotates the vault key.
Fails on any console error or CSP violation.

Run: python3 tests/browser_e2e.py   (needs `playwright`; set PW_CHANNEL=chrome to use installed Chrome)
"""
import functools
import http.server
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PORT = 8765
BASE = f"http://localhost:{PORT}/"
tmp = Path(tempfile.mkdtemp())
env = {**os.environ, "TAPSEAL_HOME": str(tmp / "home"), "TAPSEAL_SHM": str(tmp / "shm"),
       "TAPSEAL_URL": BASE, "TAPSEAL_ALLOW_DISK": "1", "PYTHONPATH": str(ROOT)}
VM = [sys.executable, "-m", "tapseal"]


def vm(*args, check=True, input=None, e=None):
    return subprocess.run(VM + list(args), env=e or env, capture_output=True, text=True, check=check, input=input)


certify_link = vm("init").stdout.strip()


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


srv = http.server.ThreadingHTTPServer(("localhost", PORT), functools.partial(Quiet, directory=str(SITE)))
threading.Thread(target=srv.serve_forever, daemon=True).start()

config = {"js": "window.TAPSEAL_CONFIG = null;"}
ttl_default = []
problems = []
n = 0


def ok(cond, msg):
    global n
    if not cond:
        print("FAIL", msg, problems)
        sys.exit(1)
    n += 1
    print(f"b{n} {msg}: OK")


with sync_playwright() as p:
    b = p.chromium.launch(channel=os.environ.get("PW_CHANNEL") or None)
    page = b.new_page()
    page.on("console", lambda m: m.type == "error" and problems.append(m.text))
    page.on("pageerror", lambda e: problems.append(str(e)))
    page.route("**/config.js", lambda r: r.fulfill(status=200, content_type="text/javascript", body=config["js"]))
    page.add_init_script("document.addEventListener('securitypolicyviolation', e => console.error('CSP ' + e.violatedDirective))")

    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "usb",
        "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True,
        "hasPrf": True, "automaticPresenceSimulation": True}})

    def load(url):
        # A fragment change alone does not reload, and the page reads config.js only on load.
        page.goto("about:blank")
        page.goto(url)

    def goto(frag):
        load(BASE + frag)
        page.wait_for_selector("h1, p.bad")

    def output():
        return page.input_value("section:has-text('Paste this into chat') textarea")

    def register(label):
        page.fill("input[placeholder^='e.g. yk-nfc']", label)
        page.click("text=Register key")
        page.wait_for_selector(f"text=Registered {label}.", timeout=15000)

    def generate_config():
        page.click("text=Generate config.js")
        page.wait_for_selector(".paper")
        paper = page.inner_text(".paper").strip()
        page.check(".warn input[type=checkbox]")
        page.click("text=Generate config.js")
        page.wait_for_selector("section:has-text('config.js') textarea")
        return paper, page.input_value("section:has(h2:text-is('config.js')) textarea")

    def certify():
        load(vm("certify-link").stdout.strip())
        page.wait_for_selector("text=Certify VM identity")
        page.click("text=Certify with security key")
        page.wait_for_selector("text=Paste this into chat", timeout=15000)
        return vm("certify", input=output(), check=False)

    def deliver_from(link):
        load(link)
        page.wait_for_selector("text=Unlock request")
        page.click("text=Unlock with security key")
        page.wait_for_selector("text=Verified: oura", timeout=15000)
        ttl_default.append(page.input_value("select"))
        page.click("text=Deliver to VM")
        page.wait_for_selector("text=Paste this into chat")
        return output()

    goto("#selftest")
    page.click("text=Run self test")
    page.wait_for_selector("text=PASS: this device and authenticator support what tapseal needs.", timeout=15000)
    ok(True, "PRF self test passes")

    goto("#enroll")
    page.click("text=Start")
    register("yk-nfc")
    paper, config["js"] = generate_config()
    ok('"salt"' in config["js"] and '"pageKey"' in config["js"] and '"pageSeal"' in config["js"] and '"synced"' not in config["js"] and '"rpId": "localhost"' in config["js"]
       and "vmKey" not in config["js"], "config.js generated without any VM key")

    r = certify()
    ok(r.returncode == 0 and "pinned page key" in r.stdout, "VM identity certified with one tap; page key pinned")

    goto("#seal")
    page.fill("input[placeholder='e.g. oura']", "oura")
    page.fill("textarea", '{"session":"s3cret"}')
    page.click("text=Seal with security key")
    page.wait_for_selector("text=Vault blob for oura", timeout=15000)
    blob = page.input_value("section:has-text('Vault blob') textarea")
    ok(blob.startswith("tsv1.") and page.input_value("textarea >> nth=0") == "", "sealed; plaintext field cleared")
    vm("store", blob)

    link = vm("link", "oura").stdout.strip()
    goto(link.replace(BASE, ""))
    ok(page.locator("select option").count() == 0 and "expires in" in page.inner_text("main"), "unlock view shows relative expiry")
    tsd = deliver_from(link)
    ok(ttl_default == ["300"], "delivery window defaults to the shortest option")
    r = vm("receive", input=tsd, check=False)
    ok(r.returncode == 0 and (tmp / "shm" / "oura").read_text() == '{"session":"s3cret"}', "signed delivery opens on VM")
    r = vm("receive", input=tsd, check=False)
    ok(r.returncode != 0 and "no open request" in r.stderr, "same delivery cannot be opened twice")

    goto("#u=" + link.split("#u=")[1].split("&c=")[0])
    ok(page.locator("text=Link is incomplete").count() == 1, "link without certificate and request is refused")

    oenv = {**env, "TAPSEAL_HOME": tempfile.mkdtemp(), "TAPSEAL_SHM": tempfile.mkdtemp()}
    vm("init", e=oenv)
    vm("store", blob, e=oenv)
    (Path(oenv["TAPSEAL_SHM"]) / "identity.cert").write_text(vm("link", "oura").stdout.split("&c=")[1].split("&r=")[0])
    imposter = vm("link", "oura", e=oenv).stdout.strip()
    load(imposter)
    page.wait_for_selector("text=not issued by your VM")
    ok(page.locator("text=Unlock with security key").count() == 0, "stolen certificate on another identity is refused")

    goto("#u=" + link.split("#u=")[1])
    ok(page.locator("input").count() == 0, "unlock page never offers paper key entry")

    page.route("**/config.js", lambda r: r.fulfill(status=200, content_type="text/javascript",
                                                    body=config["js"].replace('"localhost"', '"unlock.example.com"')))
    goto("")
    ok("Refusing to run" in page.inner_text("main"), "page refuses to run on a hostname other than its rpId")
    page.route("**/config.js", lambda r: r.fulfill(status=200, content_type="text/javascript", body=config["js"]))

    goto("")
    page.fill("input[placeholder^='e.g. blue']", "blue heron")
    page.click("text=Save phrase")
    goto("#seal")
    ok("blue heron" in page.inner_text("main"), "anti phishing phrase shown on every view")

    # Recovery with the paper key rotates: new vault key, blobs carried over, old paper key dead.
    old_config, old_paper = config["js"], paper
    bundle = vm("export").stdout.strip()
    goto("#recover")
    page.fill("input.mono", old_paper)
    page.click("text=Unlock with paper key")
    page.wait_for_selector("text=Paper key accepted", timeout=15000)
    register("yk-nfc-2")
    page.fill("textarea[placeholder^='tsb1']", bundle)
    new_paper, config["js"] = generate_config()
    new_bundle = page.input_value("section:has-text('Re-sealed secrets') textarea")
    ok(new_paper != old_paper and '"yk-nfc-2"' in config["js"] and '"yk-nfc"' not in config["js"].replace('"yk-nfc-2"', ''),
       "recovery rotates: new paper key, only re-registered keys remain")
    vm("import", input=new_bundle)
    vm("repin")
    vm("init", "--force")
    r = certify()
    ok(r.returncode == 0 and "pinned page key" in r.stdout, "VM re-pins the new page key after rotation")
    tsd = deliver_from(vm("link", "oura").stdout.strip())
    ttl_default.clear()
    ok(vm("receive", input=tsd, check=False).returncode == 0, "secret re-sealed under the new vault key unlocks")

    config["js"] = old_config
    goto("#recover")
    page.fill("input.mono", old_paper)
    page.click("text=Unlock with paper key")
    page.wait_for_selector("text=Paper key accepted", timeout=15000)
    register("thief")
    page.fill("textarea[placeholder^='tsb1']", new_bundle)
    page.click("text=Generate config.js")
    page.wait_for_selector("text=Blob failed authentication", timeout=15000)
    ok(True, "old paper key with old config.js cannot open re-sealed secrets")

    b.close()

srv.shutdown()
problems = [x for x in problems if "Failed to load resource" not in x]
ok(not problems, "no console errors or CSP violations")
