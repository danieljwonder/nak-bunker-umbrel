#!/usr/bin/env python3
"""End-to-end test of the shim with the REAL nak binary and real public relays.

Usage: NAK_BIN=/path/to/nak PKG=/path/with/node_modules python3 -I tests/e2e_local.py
Uses a throwaway key in a temp HOME. Signs nothing that gets published.
"""
import json, os, re, shutil, signal, subprocess, sys, tempfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM = os.path.join(HERE, "..", "shim", "nakbunker.py")
NAK = os.environ["NAK_BIN"]
PORT = int(os.environ.get("TEST_PORT", "18951"))
RELAYS = os.environ.get("TEST_RELAYS", "wss://relay.nip46.com\nwss://nrs.primal.net\nwss://bucket.coracle.social")
PW = "correct horse battery"
FAILS = 0


def check(label, cond, extra=""):
    global FAILS
    print(("PASS" if cond else "FAIL") + ": " + label + (f"  [{extra}]" if extra and not cond else ""), flush=True)
    FAILS += 0 if cond else 1


def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
        return r.read().decode()


def status():
    return json.loads(get("/api/status"))


def post(path, data, token):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method="POST",
                                 data=urllib.parse.urlencode(data).encode(),
                                 headers={"X-CSRF": token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def wait(pred, secs=60):
    end = time.time() + secs
    while time.time() < end:
        s = status()
        if pred(s):
            return s
        time.sleep(1)
    return status()


DM_RELAY = os.environ.get("TEST_DM_RELAY", "wss://bucket.coracle.social")
USER_SEC = subprocess.run([NAK, "key", "generate"], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.strip()
USER_PUB = subprocess.run([NAK, "key", "public", USER_SEC], capture_output=True, text=True, stdin=subprocess.DEVNULL).stdout.strip()


def start_shim(home, **extra):
    env = dict(os.environ, NAK_BIN=NAK, NAK_HOME=home, PORT=str(PORT), FALLBACK_DM_RELAYS=DM_RELAY,
               LOOKUP_RELAYS=DM_RELAY, **extra)
    p = subprocess.Popen([sys.executable, "-I", SHIM], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            get("/api/status")
            break
        except Exception:
            time.sleep(0.2)
    page = get("/")
    token = re.search(r'const T="([^"]+)"', page).group(1)
    return p, token


CLIENT_HEX = os.urandom(32).hex()


def inbox(since):
    """Unwrap every NIP-17 DM to the test user on the DM relay since `since`; return (rumor, wrap) pairs."""
    req = subprocess.run([NAK, "req", "-k", "1059", "-p", USER_PUB, DM_RELAY], capture_output=True, text=True,
                         timeout=60, stdin=subprocess.DEVNULL)
    out = []
    for line in req.stdout.splitlines():
        u = subprocess.run([NAK, "gift", "unwrap"], input=line, capture_output=True, text=True, timeout=30,
                           env=dict(os.environ, NOSTR_SECRET_KEY=USER_SEC))
        try:
            r = json.loads(u.stdout.strip().splitlines()[-1])
        except Exception:
            continue
        if r.get("created_at", 0) >= since - 5:
            out.append((r, json.loads(line)))
    return out


def client(uri, mode=""):
    out = subprocess.run(["node", os.path.join(HERE, "nip46_client.mjs"), uri, mode, CLIENT_HEX], capture_output=True, text=True, timeout=90)
    try:
        return json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        return {"error": out.stderr[-300:]}


import urllib.parse  # noqa: E402

home = tempfile.mkdtemp(prefix="nakbunker-e2e-")
p, tok = start_shim(home)
try:
    s = status()
    check("fresh install shows setup, nak not started", s["state"] == "setup")
    check("POST without CSRF token refused", post("/api/setup", {"mode": "generate"}, None)[0] == 403)
    check("short password refused", post("/api/setup", {"mode": "generate", "password": "short", "relays": RELAYS}, tok)[0] == 400)
    check("bad ncryptsec password refused before saving",
          post("/api/setup", {"mode": "import-ncryptsec", "key": "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p", "password": "wrong password!!", "relays": RELAYS}, tok)[0] == 400)
    check("still no config written", not os.path.exists(os.path.join(home, ".config/nak/bunker/default")))

    code, _ = post("/api/setup", {"mode": "import-nsec", "key": USER_SEC, "password": PW, "relays": RELAYS}, tok)
    check("setup (import hex key) accepted", code == 200)
    cfg = json.load(open(os.path.join(home, ".config/nak/bunker/default")))
    check("config holds only an encrypted key", cfg["sec"].startswith("ncryptsec1"))
    check("config file mode 600", oct(os.stat(os.path.join(home, ".config/nak/bunker/default")).st_mode & 0o777) == "0o600")
    s = wait(lambda s: s["state"] == "running" and s["bunker_uri"], 90)
    check("nak unlocked and running", s["state"] == "running", s["state"] + " " + s["message"])
    check("bunker URI shown", bool(s["bunker_uri"]))
    ok_relays = [r for r, st in s["relay_status"].items() if st == "ok"]
    check("at least 2 relays ok", len(ok_relays) >= 2, str(s["relay_status"]))
    logtext = json.dumps(s["log"])
    check("password never in log", PW not in logtext)
    check("no ncryptsec/nsec/secret value in log", not re.search(r"ncryptsec1[0-9a-z]{10}|nsec1[0-9a-z]{10}|secret=[A-Za-z0-9]{4}", logtext))

    r = client(s["bunker_uri"])
    check("real NIP-46 client: connect + get_public_key + sign_event", r.get("connect") == "ok" and r.get("signed") is True, str(r))
    pub = r.get("pubkey")
    s = wait(lambda s: len(s["clients"]) >= 1, 15)
    check("client persisted as authorised", len(s["clients"]) == 1)
    client_pk = s["clients"][0]["pubkey"] if s["clients"] else ""

    # nak dies -> shim restarts it and re-unlocks from memory
    nak_pid = int(subprocess.run(["pgrep", "-f", "-n", NAK + " bunker"], capture_output=True, text=True).stdout.split()[0])
    os.kill(nak_pid, signal.SIGKILL)
    s = wait(lambda s: s["state"] != "running", 15)
    s = wait(lambda s: s["state"] == "running", 90)
    check("nak killed -> restarted and unlocked unattended", s["state"] == "running", s["state"] + " " + s["message"])
    r = client(s["bunker_uri"].split("&secret=")[0], "noconnect")
    check("authorised client still works after restart", r.get("pubkey") == pub, str(r))

    # relay edit -> restart with new list
    code, _ = post("/api/relays", {"relays": RELAYS + "\nwss://relay.damus.io"}, tok)
    s = wait(lambda s: s["state"] == "running" and "wss://relay.damus.io" in s["relays"], 90)
    check("relay list edited and nak restarted", s["state"] == "running" and len(s["relays"]) == 4)

    # ---- locked reminders: test DM
    check("owner npub learned at unlock", s["notify"]["ready"] and s["notify"]["enabled"])
    # publish a NIP-17 DM relay list (kind 10050) for the test user, so delivery must use it
    subprocess.run([NAK, "event", "-k", "10050", "-t", "relay=" + DM_RELAY, DM_RELAY], capture_output=True, text=True,
                   timeout=60, stdin=subprocess.DEVNULL, env=dict(os.environ, NOSTR_SECRET_KEY=USER_SEC))
    time.sleep(2)
    t0 = int(time.time())
    code, j = post("/api/notify/test", {}, tok)
    check("test DM accepted by a relay", code == 200, str(j))
    check("delivered via the owner's kind 10050 DM relays", "kind 10050" in j.get("message", ""), str(j))
    st = json.load(open(os.path.join(home, "nakbunker-shim.json")))
    check("state file mode 600", oct(os.stat(os.path.join(home, "nakbunker-shim.json")).st_mode & 0o777) == "0o600")
    time.sleep(3)
    msgs = inbox(t0)
    r = next((m for m in msgs if "Test from nak bunker" in m[0].get("content", "")), None)
    check("test DM arrives and unwraps for the owner (NIP-17 kind 14)", r is not None and r[0]["kind"] == 14, str(len(msgs)))
    if r:
        check("rumor is from this install's notifier key, not the owner", r[0]["pubkey"] == st.get("notifier_pub") != USER_PUB)
        check("outer wrap signed by a one-time key", r[1]["pubkey"] not in (st.get("notifier_pub"), USER_PUB))
        check("message has no links", "http" not in r[0]["content"] and "://" not in r[0]["content"])
    s = status()
    check("notifier secret never exposed", st.get("notifier_sec", "x") not in json.dumps(s) + json.dumps(s["log"]))
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)

# app restart: password is gone; reminder fires while locked; then wrong and right passwords
p, tok = start_shim(home, LOCK_NOTIFY_SECS="5")
try:
    s = wait(lambda s: s["state"] == "locked", 30)
    check("after app restart: locked, waiting for password", s["state"] == "locked")
    t0 = int(time.time())
    before = s["notify"]["last"]
    s = wait(lambda s: s["notify"]["last"] and s["notify"]["last"] != before, 90)
    check("locked reminder sent automatically", s["notify"]["last"] != before, s["notify"]["last_result"])
    time.sleep(3)
    check("locked reminder arrives and unwraps", any("restarted and is locked" in m[0].get("content", "") for m in inbox(t0)))
    last = s["notify"]["last"]
    time.sleep(35)
    check("no repeat within the reminder interval", status()["notify"]["last"] == last)
    post("/api/unlock", {"password": "not the password", "remember": "1"}, tok)
    s = wait(lambda s: "Wrong" in s["message"], 30)
    check("wrong password reported", "Wrong" in s["message"], s["message"])
    check("wrong password not remembered", s["remembered"] is False)
    post("/api/unlock", {"password": PW, "remember": ""}, tok)
    s = wait(lambda s: s["state"] == "running", 60)
    check("right password on retry unlocks", s["state"] == "running", s["state"] + " " + s["message"])
    check("remember off -> not kept in memory", s["remembered"] is False)
    check("passwords never in log", PW not in json.dumps(s["log"]) and "not the password" not in json.dumps(s["log"]))
    code, _ = post("/api/client/remove", {"pubkey": client_pk}, tok)
    s = wait(lambda s: len(s["clients"]) == 0, 20)
    check("client removed", code == 200 and len(s["clients"]) == 0)
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)

# unlocking before the delay sends nothing
p, tok = start_shim(home, LOCK_NOTIFY_SECS="40")
try:
    s = wait(lambda s: s["state"] == "locked", 30)
    last = s["notify"]["last"]
    post("/api/unlock", {"password": PW, "remember": ""}, tok)
    s = wait(lambda s: s["state"] == "running", 60)
    time.sleep(55)
    check("unlocked before the delay: no reminder sent", status()["notify"]["last"] == last)
finally:
    p.send_signal(signal.SIGTERM)
    p.wait(timeout=15)
    leftover = subprocess.run(["pgrep", "-f", NAK + " bunker"], capture_output=True, text=True).stdout.strip()
    check("no nak process left behind", leftover == "", leftover)
    shutil.rmtree(home, ignore_errors=True)

print("\nALL E2E CHECKS PASSED" if FAILS == 0 else f"\n{FAILS} E2E CHECKS FAILED")
sys.exit(1 if FAILS else 0)
