#!/usr/bin/env python3
"""nak bunker for Umbrel: a thin web shim around the upstream `nak bunker`.

nak does the signing (unmodified upstream release binary). This file only:
  - runs `nak bunker --persist` in a pseudo-terminal so it can be unlocked
    from a web page instead of `docker attach`,
  - writes the first config (encrypted key + relays) so nak never starts
    with its machine-default key,
  - shows status, relays, authorised clients and the bunker:// URI,
  - restarts nak if it exits, re-entering the password if you chose to keep
    the bunker unlocked until the app itself restarts.

Python standard library only. Auth is Umbrel's app proxy; every POST also
needs a per-process CSRF token. Secrets are never logged.
"""
import errno, fcntl, html, json, os, pty, re, secrets, select, signal, struct, subprocess
import termios, threading, time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

NAK = os.environ.get("NAK_BIN", "/usr/local/bin/nak")
HOME = os.environ.get("NAK_HOME", "/data")
CONFIG = os.path.join(HOME, ".config", "nak", "bunker", "default")
PORT = int(os.environ.get("PORT", "8080"))
DEFAULT_RELAYS = [r for r in os.environ.get(
    "DEFAULT_RELAYS", "wss://relay.nip46.com,wss://nrs.primal.net,wss://bucket.coracle.social").split(",") if r]
CSRF = secrets.token_urlsafe(24)

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]|[\x00-\x08\x0b-\x1f\x7f]")
P_SEC = "type your secret key as ncryptsec, nsec or hex"
P_PW = "type the password to decrypt your secret key"
P_PW_RE = re.compile(r"type the password to decrypt your secret key(?: \[(\d)/3\])?")
RELAY_LINE = re.compile(r"^(wss?://\S+?)\.\.\.\s*(.*)$")
BUNKER_LINE = re.compile(r"bunker:\s*(bunker://\S+)")


def mask(s, pw=None):
    s = re.sub(r"ncryptsec1[0-9a-z]+", "ncryptsec1…", s)
    s = re.sub(r"nsec1[0-9a-z]+", "nsec1…", s)
    s = re.sub(r"(secret=)[^&\s\"']+", r"\1…", s)
    if pw:
        s = s.replace(pw, "•••")
    return s


def short_relay_error(msg):
    """One short reason for the UI; the full text stays in the log."""
    m = re.search(r"(?:but got|HTTP/\S+) (\d{3})", msg)
    if m:
        return "HTTP " + m.group(1)
    if "expected handshake" in msg:
        return "refused (relay busy or blocking)"
    for k, v in (("no such host", "DNS lookup failed"), ("timeout", "timed out"), ("deadline", "timed out"),
                 ("connection refused", "connection refused"), ("certificate", "TLS error"),
                 ("failed to send handshake", "unreachable")):
        if k in msg.lower():
            return v
    return "failed"


def read_config():
    try:
        with open(CONFIG) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def write_config(cfg):
    os.makedirs(os.path.dirname(CONFIG), mode=0o700, exist_ok=True)
    tmp = CONFIG + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG)


# ---------------------------------------------------------------- locked reminders (NIP-17 DMs)
#
# When nak sits at its password prompt for LOCK_NOTIFY_SECS, send the owner a NIP-17 DM (kind 14
# rumor, sealed and gift-wrapped per NIP-59, built by nak itself) from a per-install notifier key,
# then a reminder every LOCK_REMIND_SECS while it stays locked. The notifier key is generated with
# nak (OS CSPRNG) on first use, is unique to this install and can only send these notices. The
# owner's pubkey is remembered from the last successful unlock (it can't be read while locked).
# Messages contain no links, so a forged one can't send anyone to a fake password page.

STATE_FILE = os.path.join(HOME, "nakbunker-shim.json")
LOCK_NOTIFY_SECS = int(os.environ.get("LOCK_NOTIFY_SECS", "600"))
LOCK_REMIND_SECS = int(os.environ.get("LOCK_REMIND_SECS", "86400"))
LOOKUP_RELAYS = [r for r in os.environ.get(
    "LOOKUP_RELAYS", "wss://purplepag.es,wss://user.kindpag.es,wss://relay.damus.io,wss://relay.primal.net").split(",") if r]
FALLBACK_DM_RELAYS = [r for r in os.environ.get(
    "FALLBACK_DM_RELAYS", "wss://relay.damus.io,wss://relay.primal.net,wss://nos.lol").split(",") if r]
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def load_state():
    try:
        with open(STATE_FILE) as f:
            s = json.load(f)
            return s if isinstance(s, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def save_state(s):
    tmp = STATE_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f, indent=2)
    os.replace(tmp, STATE_FILE)


def nak_io(args, stdin=None, sec=None, timeout=60):
    """Run nak with optional stdin; a key goes in via env, never argv or logs."""
    env = {"HOME": HOME, "PATH": "/usr/bin:/bin"}
    if sec:
        env["NOSTR_SECRET_KEY"] = sec
    # nak treats a piped stdin as event/filter input, so give it /dev/null when there is none:
    # an empty pipe makes `nak req` silently ignore its command-line filters.
    io = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
    p = subprocess.run([NAK] + args, capture_output=True, text=True, timeout=timeout, env=env, **io)
    return p.returncode, p.stdout, p.stderr


class Notifier:
    def __init__(self, bunker):
        self.b = bunker
        self.lock = threading.Lock()
        self.busy = False

    def state(self):
        return load_state()

    def notifier_key(self):
        s = load_state()
        if not HEX64.match(s.get("notifier_sec", "")):
            code, out, _ = nak_io(["key", "generate"])
            sec = out.strip()
            if code != 0 or not HEX64.match(sec):
                raise ValueError("could not generate a notifier key")
            s["notifier_sec"] = sec
            code, out, _ = nak_io(["key", "public", sec])
            s["notifier_pub"] = out.strip()
            code, out, _ = nak_io(["encode", "npub", s["notifier_pub"]])
            s["notifier_npub"] = out.strip()
            save_state(s)
        return s["notifier_sec"]

    def dm_relays(self, pub):
        """NIP-17: the recipient's kind 10050 relays; else their kind 10002 read relays; else fallbacks."""
        lookup = list(dict.fromkeys(LOOKUP_RELAYS + (read_config() or {}).get("relays", [])))
        code, out, _ = nak_io(["req", "-k", "10050", "-k", "10002", "-a", pub, "-l", "10"] + lookup, timeout=30)
        newest = {}
        for line in out.splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if e.get("pubkey") == pub and e.get("created_at", 0) > newest.get(e.get("kind"), {}).get("created_at", -1):
                newest[e["kind"]] = e
        dm = [t[1] for t in newest.get(10050, {}).get("tags", []) if len(t) > 1 and t[0] == "relay"]
        if dm:
            return dm[:8], "your DM relays (kind 10050)"
        rd = [t[1] for t in newest.get(10002, {}).get("tags", [])
              if len(t) > 1 and t[0] == "r" and (len(t) == 2 or t[2] == "read")]
        if rd:
            return rd[:8], "your read relays (kind 10002)"
        return FALLBACK_DM_RELAYS, "fallback relays (no kind 10050 or 10002 found)"

    def send(self, text):
        """Returns (accepted, tried, where). Never raises for relay failures."""
        s = load_state()
        pub = s.get("user_pubkey", "")
        if not HEX64.match(pub):
            raise ValueError("Unlock once first, so the bunker knows which npub to message.")
        sec = self.notifier_key()
        relays, where = self.dm_relays(pub)
        code, rumor, err = nak_io(["event", "-k", "14", "-p", pub, "-c", text], sec=sec)
        if code != 0:
            raise ValueError("nak could not build the message")
        code, wrap, err = nak_io(["gift", "wrap", "-p", pub], stdin=rumor, sec=sec)
        if code != 0 or '"kind":1059' not in wrap.replace(" ", ""):
            raise ValueError("nak could not gift-wrap the message")
        code, out, err = nak_io(["event"] + relays, stdin=wrap, timeout=60)
        accepted = len(re.findall(r"publishing to \S+\.\.\. success", err))
        s = load_state()
        s["last_notice"] = int(time.time())
        s["last_notice_result"] = f"{accepted}/{len(relays)} relays accepted ({where})"
        save_state(s)
        self.b.add_log(f"[shim] notice sent: {s['last_notice_result']}")
        return accepted, len(relays), where

    def loop(self):
        while True:
            time.sleep(15)
            try:
                self.tick()
            except Exception as e:  # never let the reminder thread die
                self.b.add_log(f"[shim] reminder error: {type(e).__name__}")

    def tick(self):
        b = self.b
        with b.lock:
            since = b.locked_since if (b.state == "locked" and b.proc_pid) else None
            last = b.episode_notice
        s = load_state()
        if since is None or not s.get("notify", True) or not HEX64.match(s.get("user_pubkey", "")):
            return
        now = time.time()
        if now - since < LOCK_NOTIFY_SECS:
            return
        if last and now - last < LOCK_REMIND_SECS:
            return
        if last:
            hrs = int((now - since) // 3600)
            text = (f"Your nak bunker is still locked ({hrs} h). Apps can't sign until you open "
                    "your nak bunker page and enter your password.")
        else:
            text = ("Your nak bunker restarted and is locked. Apps can't sign until you open "
                    "your nak bunker page and enter your password.")
        with b.lock:
            b.episode_notice = now  # set before sending: a relay outage must not cause a burst
        self.send(text)


def has_encrypted_key(cfg):
    return bool(cfg) and isinstance(cfg.get("sec"), str) and cfg["sec"].startswith("ncryptsec1")


def norm_relay(u):
    u = u.strip()
    if not u:
        return None
    if "://" not in u:
        u = "wss://" + u
    if not re.match(r"^wss?://[A-Za-z0-9.-]+(:\d+)?(/[^\s]*)?$", u):
        raise ValueError(f"not a relay URL: {u}")
    return u.rstrip("/")


class Bunker:
    """Owns the nak process and everything parsed from its output."""

    def __init__(self):
        self.lock = threading.RLock()
        self.proc_pid = None
        self.fd = None
        self.log = deque(maxlen=300)
        self.state = "stopped"     # setup | starting | locked | running | stopped | error
        self.message = ""
        self.password = None       # kept in RAM only if the user chose to
        self.pending_pw = None     # one-shot answer for the next prompt
        self.prompt_answered = False
        self.relay_status = {}
        self.bunker_uri = None
        self.started_at = None
        self.restarts = 0
        self.wrong_pw = False
        self.answered_attempt = 0
        self.awaiting_attempt = 0
        self.locked_since = None   # start of the current locked episode (for reminders)
        self.episode_notice = None
        self.want_running = True
        self._line = ""

    # ---------------- process control ----------------
    def start(self):
        with self.lock:
            if self.proc_pid:
                return
            cfg = read_config()
            if not has_encrypted_key(cfg):
                # Never start nak without an encrypted key: it would sign with
                # its machine-default key.
                self.state = "setup"
                return
            self.state = "starting"
            self.relay_status = {r: "connecting" for r in cfg.get("relays") or []}
            self.bunker_uri = None
            self.prompt_answered = False
            self.answered_attempt = 0
            self.awaiting_attempt = 0
            self.wrong_pw = False
            pid, fd = pty.fork()
            if pid == 0:
                os.environ["HOME"] = HOME
                os.environ["TERM"] = "dumb"
                os.environ.pop("NOSTR_SECRET_KEY", None)
                try:
                    os.execv(NAK, [NAK, "bunker", "--persist"])
                finally:
                    os._exit(127)
            # No echo: a password typed before nak switches to raw mode must not
            # come back out of the terminal into our log.
            attrs = termios.tcgetattr(fd)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 220, 0, 0))
            self.proc_pid, self.fd = pid, fd
            self.started_at = time.time()
            self.add_log(f"[shim] started nak (pid {pid})")
            threading.Thread(target=self._reader, args=(pid, fd), daemon=True).start()

    def stop(self):
        with self.lock:
            pid = self.proc_pid
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(50):
                with self.lock:
                    if self.proc_pid is None:
                        return
                time.sleep(0.1)
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def restart(self, why):
        self.add_log(f"[shim] restarting nak: {why}")
        self.stop()
        self.start()

    def _reader(self, pid, fd):
        while True:
            try:
                r, _, _ = select.select([fd], [], [], 1.0)
                if not r:
                    continue
                data = os.read(fd, 65536)
                if not data:
                    break
            except OSError as e:
                if e.errno in (errno.EIO, errno.EBADF):
                    break
                raise
            self._feed(data.decode("utf8", "replace"))
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        with self.lock:
            try:
                os.close(fd)
            except OSError:
                pass
            self.proc_pid = self.fd = None
            self.add_log(f"[shim] nak exited with code {code}")
            if self.wrong_pw:
                self.state, self.message = "locked", "Wrong password."
            elif code == 3:
                self.state, self.message = "error", "Could not connect to any relay. Retrying."
            else:
                self.state = "stopped"
            self.pending_pw = None
            want = self.want_running
        if want:
            # Back off so a crash loop can't hammer relays; restart sooner when
            # we hold the password (unattended recovery).
            self.restarts += 1
            delay = min(300, 5 * self.restarts) if self.password else 2
            time.sleep(delay)
            self.start()

    def _feed(self, text):
        with self.lock:
            buf = self._line + text
            # Prompts are redrawn without newlines; check the raw buffer.
            flat = ANSI.sub("", buf)
            prompts = P_PW_RE.findall(flat)
            if prompts:
                attempt = int(prompts[-1] or 1)
                if attempt > self.answered_attempt:
                    # A fresh prompt. attempt > 1 means the last answer was wrong.
                    if attempt > 1:
                        self.message = "Wrong password."
                        self.password = None   # never keep retrying a bad one
                    self.prompt_answered = False
                    self.state = "locked"
                    answer = self.pending_pw or (self.password if attempt == 1 else None)
                    if answer:
                        self.answered_attempt = attempt
                        self.prompt_answered = True
                        self.pending_pw = None
                        os.write(self.fd, (answer + "\r").encode())
                        self.state = "starting"
                        self.message = "Unlocking…"
                    else:
                        self.awaiting_attempt = attempt
                        if self.locked_since is None:
                            self.locked_since = time.time()
            if P_SEC in flat and not self.prompt_answered:
                # Should not happen (we always pre-write the config); refuse to
                # type a key into nak from here.
                self.state, self.message = "error", "nak asked for a key; check the config."
            parts = re.split(r"[\r\n]+", buf)
            self._line = parts.pop()
            if len(self._line) > 4000:
                self._line = self._line[-4000:]
            for raw in parts:
                self._line_done(raw)

    def _line_done(self, raw):
        line = ANSI.sub("", raw).strip()
        if not line or P_PW in line or P_SEC in line:
            return
        if "couldn't decrypt" in line:
            self.wrong_pw = True
            self.message = "Wrong password."
            if self.password:
                self.password = None  # stale; don't keep retrying it
        m = RELAY_LINE.match(line)
        if m:
            url, rest = m.group(1), m.group(2).strip()
            if rest:
                self.relay_status[url] = "ok" if rest.startswith("ok") else short_relay_error(rest)
        m = BUNKER_LINE.search(line)
        if m:
            self.bunker_uri = m.group(1)
        m = re.match(r"pubkey:\s*([0-9a-f]{64})", line)
        if m:
            st = load_state()
            if st.get("user_pubkey") != m.group(1):
                st["user_pubkey"] = m.group(1)
                save_state(st)
        if line.startswith("listening at"):
            self.state, self.message = "running", ""
            self.locked_since = None
            self.episode_notice = None
            self.restarts = 0
            self.wrong_pw = False
        self.add_log(line)

    def add_log(self, line):
        self.log.append((time.strftime("%Y-%m-%d %H:%M:%S"), mask(line, self.password)))

    # ---------------- user actions ----------------
    def unlock(self, password, remember):
        with self.lock:
            if remember:
                self.password = password
            self.pending_pw = password
            self.message = "Unlocking…"
            if self.proc_pid and self.state == "locked" and not self.prompt_answered and self.awaiting_attempt:
                self.prompt_answered = True
                self.answered_attempt = self.awaiting_attempt
                self.pending_pw = None
                os.write(self.fd, (password + "\r").encode())
                self.state = "starting"
                return
        if not self.proc_pid:
            self.start()

    def setup(self, mode, key, password, relays):
        if len(password) < 8:
            raise ValueError("Use a password of at least 8 characters.")
        if read_config() and has_encrypted_key(read_config()):
            raise ValueError("A key is already configured.")
        if mode == "import-ncryptsec":
            if not key.startswith("ncryptsec1"):
                raise ValueError("That is not an ncryptsec1… string.")
            try:
                # key via stdin, not argv; output (the plain key) is discarded
                if nak_io(["key", "decrypt", password], stdin=key + "\n")[0] != 0:
                    raise ValueError("bad password")
            except ValueError:
                raise ValueError("That password does not decrypt this ncryptsec.")
            ncs = key
        else:
            if mode == "generate":
                key = run_nak(["key", "generate"])
            elif not (key.startswith("nsec1") or re.fullmatch(r"[0-9a-f]{64}", key)):
                raise ValueError("Paste an nsec1… or 64-character hex key.")
            # key via stdin so it never appears in a process list; nak only takes the password as an
            # argument, for the under-a-second this setup step runs (unlocking uses the terminal)
            code, out, _ = nak_io(["key", "encrypt", password], stdin=key + "\n")
            ncs = out.strip() if code == 0 else ""
            if not ncs.startswith("ncryptsec1"):
                raise ValueError("Encrypting the key failed.")
        write_config({"clients": None, "sec": ncs, "relays": relays})
        self.add_log("[shim] wrote encrypted key and relays to config")
        self.unlock(password, remember=True)

    def set_relays(self, relays):
        cfg = read_config()
        if not cfg:
            raise ValueError("No config yet.")
        cfg["relays"] = relays
        write_config(cfg)
        self.restart("relay list changed")

    def remove_client(self, pubkey):
        cfg = read_config() or {}
        before = cfg.get("clients") or []
        cfg["clients"] = [c for c in before if c.get("pubkey") != pubkey] or None
        write_config(cfg)
        self.restart("client removed")

    def snapshot(self):
        with self.lock:
            cfg = read_config() or {}
            return {
                "state": self.state if self.state != "stopped" or has_encrypted_key(cfg) else "setup",
                "message": self.message,
                "remembered": self.password is not None,
                "relays": cfg.get("relays") or [],
                "relay_status": dict(self.relay_status),
                "clients": [{"pubkey": c.get("pubkey", ""), "name": c.get("name", ""), "url": c.get("url", "")}
                            for c in (cfg.get("clients") or [])],
                "bunker_uri": self.bunker_uri,
                "started_at": self.started_at,
                "log": list(self.log)[-80:],
                "notify": notify_view(),
            }


def notify_view():
    st = load_state()
    return {
        "enabled": st.get("notify", True),
        "ready": bool(HEX64.match(st.get("user_pubkey", ""))),
        "from_npub": st.get("notifier_npub", ""),
        "last": st.get("last_notice"),
        "last_result": st.get("last_notice_result", ""),
        "after_min": LOCK_NOTIFY_SECS // 60,
    }


def run_nak(args):
    # Runs in this container only; the key never leaves it.
    out = subprocess.run([NAK] + args, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
                         env={"HOME": HOME, "PATH": "/usr/bin:/bin"})
    if out.returncode != 0:
        raise ValueError("nak failed: " + mask(out.stderr.strip())[:200])
    return out.stdout.strip()


BUNKER = Bunker()
NOTIFIER = Notifier(BUNKER)

# ---------------------------------------------------------------- web UI

PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>nak bunker</title><style>
body{font-family:-apple-system,system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
.w{max-width:760px;margin:0 auto;padding:16px}h1{font-size:20px}h2{font-size:15px;margin:0 0 8px;color:#9aa4b2}
.c{background:#181b22;border:1px solid #262b36;border-radius:10px;padding:14px 16px;margin-bottom:12px}
.ok{color:#4ade80}.bad{color:#f87171}.unk{color:#fbbf24}code,pre,.m{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
pre{white-space:pre-wrap;max-height:280px;overflow:auto;margin:0}
input,textarea,select{background:#0f1115;color:#e6e6e6;border:1px solid #3a4356;border-radius:8px;padding:8px;width:100%;box-sizing:border-box;margin:4px 0}
button{background:#2b3342;color:#e6e6e6;border:1px solid #3a4356;border-radius:8px;padding:8px 14px;cursor:pointer;margin:6px 6px 0 0}
li{margin:4px 0}small{color:#9aa4b2}label{display:block;margin-top:6px}
</style></head><body><div class="w"><h1>nak bunker</h1><div id="app">Loading…</div></div>
<script>
const T="__CSRF__";const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function post(p,d){const r=await fetch(p,{method:'POST',headers:{'X-CSRF':T,'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d)});const j=await r.json().catch(()=>({}));if(!r.ok)alert(j.error||r.status);load();}
let typing=false;
async function load(){if(typing)return;const s=await (await fetch('api/status')).json();let h='';
const badge={running:'<span class="ok">● running</span>',locked:'<span class="unk">● locked: enter your password</span>',starting:'<span class="unk">● starting…</span>',setup:'<span class="unk">● not set up</span>',error:'<span class="bad">● '+esc(s.message)+'</span>',stopped:'<span class="bad">● stopped</span>'}[s.state]||esc(s.state);
h+='<div class="c"><h2>Status</h2>'+badge+(s.message&&s.state!=='error'?' <small>'+esc(s.message)+'</small>':'')+(s.state==='running'?'<br><small>'+(s.remembered?'Stays unlocked until the app restarts (password held in memory).':'Unlocked. nak restarts will ask for the password again.')+'</small>':'')+'</div>';
if(s.state==='setup'){h+='<div class="c"><h2>Set up your key</h2><select id="mode" onchange="sm()"><option value="import-ncryptsec">Import an encrypted key (ncryptsec1…)</option><option value="import-nsec">Import nsec / hex (it will be encrypted)</option><option value="generate">Generate a new key</option></select><div id="kf"><label>Key</label><input id="key" type="password" autocomplete="off"></div><label>Password <small>(for ncryptsec: its existing password; otherwise a new one)</small></label><input id="pw" type="password" autocomplete="new-password"><label>Relays, one per line</label><textarea id="rl" rows="4">'+esc((s.relays.length?s.relays:__DEFAULT_RELAYS__).join('\\n'))+'</textarea><button onclick="setup()">Save and start</button><p><small>The key is stored only encrypted (NIP-49) in this app\\'s data folder.</small></p></div>';}
if(s.state==='locked'){h+='<div class="c"><h2>Unlock</h2><input id="pw" type="password" autocomplete="current-password" placeholder="password" onkeydown="if(event.key===\\'Enter\\')unlock()"><label><input type="checkbox" id="rem" checked style="width:auto"> Keep unlocked until the app restarts (lets the bunker recover from nak restarts on its own)</label><button onclick="unlock()">Unlock</button></div>';}
if(s.bunker_uri){h+='<div class="c"><h2>Connect a new app</h2><small>Paste this into the app you want to sign with. The secret is single-use and changes after each new connection.</small><p class="m" id="buri">'+esc(s.bunker_uri.replace(/secret=[^&]+/,'secret=••••••'))+'</p><button onclick="navigator.clipboard.writeText('+esc(JSON.stringify(s.bunker_uri))+');this.textContent=\\'Copied\\'">Copy bunker URI</button></div>';}
if(s.state!=='setup'){h+='<div class="c"><h2>Relays</h2><ul>'+s.relays.map(r=>{const st=s.relay_status[r];return '<li class="m">'+esc(r)+' '+(st==='ok'?'<span class="ok">ok</span>':st?'<span class="bad">'+esc(st)+'</span>':'')+'</li>'}).join('')+'</ul><textarea id="rl" rows="4" onfocus="typing=true" onblur="typing=false">'+esc(s.relays.join('\\n'))+'</textarea><button onclick="relays()">Save relays and restart</button><br><small>Use at least 3. The bunker reconnects to dropped relays on its own.</small></div>';
h+='<div class="c"><h2>Authorised apps</h2>'+(s.clients.length?'<ul>'+s.clients.map(c=>'<li><span class="m">'+esc(c.pubkey.slice(0,16))+'…</span> '+esc(c.name||'')+' <small>'+esc(c.url||'')+'</small> <button onclick="if(confirm(\\'Remove this app? It will need a new bunker URI to sign again.\\'))post(\\'api/client/remove\\',{pubkey:\\''+esc(c.pubkey)+'\\'})">Remove</button></li>').join('')+'</ul>':'<small>None yet.</small>')+'</div>';
const n=s.notify;h+='<div class="c"><h2>Locked reminders</h2><label><input type="checkbox" style="width:auto" '+(n.enabled?'checked':'')+' onchange="setnotify(this)"> Send me an encrypted Nostr DM (NIP-17) if the bunker stays locked for '+n.after_min+' minutes, then once a day until it is unlocked</label>'+(n.ready?'':'<p><small>Available after the first unlock (that is how the bunker learns your npub).</small></p>')+(n.from_npub?'<p><small>Messages come from <span class="m">'+esc(n.from_npub)+'</span>, a key unique to this install. Add it as a contact if your app hides messages from strangers. Apps that only support older (NIP-04) DMs will not show them.</small></p>':'')+(n.last?'<p><small>Last message: '+esc(new Date(n.last*1000).toLocaleString())+' &middot; '+esc(n.last_result)+'</small></p>':'')+(n.ready?'<button onclick="testdm(this)">Send test DM</button>':'')+'</div>';}
h+='<div class="c"><h2>Log</h2><pre>'+s.log.map(l=>esc(l[0]+'  '+l[1])).join('\\n')+'</pre></div>';
$('#app').innerHTML=h;}
function sm(){$('#kf').style.display=$('#mode').value==='generate'?'none':'block'}
function setup(){post('api/setup',{mode:$('#mode').value,key:$('#key').value,password:$('#pw').value,relays:$('#rl').value})}
function setnotify(c){post('api/notify',{enabled:c.checked?'1':''})}
async function testdm(b){b.disabled=true;b.textContent='Sending…';const r=await fetch('api/notify/test',{method:'POST',headers:{'X-CSRF':T}});const j=await r.json().catch(()=>({}));alert(r.ok?j.message:(j.error||r.status));load();}
function unlock(){post('api/unlock',{password:$('#pw').value,remember:$('#rem').checked?'1':''})}
function relays(){typing=false;post('api/relays',{relays:$('#rl').value})}
document.addEventListener('focusin',e=>{if(e.target.matches('input,textarea,select'))typing=true});
document.addEventListener('focusout',()=>{setTimeout(()=>{typing=!!document.activeElement&&document.activeElement.matches('input,textarea,select')},0)});
load();setInterval(load,3000);
</script></body></html>"""


def parse_relays(text):
    out = []
    for line in re.split(r"[\s,]+", text or ""):
        r = norm_relay(line)
        if r and r not in out:
            out.append(r)
    if not out:
        raise ValueError("Add at least one relay.")
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "nak-bunker"

    def log_message(self, *a):  # keep request lines (and any query strings) out of logs
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (PAGE.replace("__CSRF__", CSRF)
                    .replace("__DEFAULT_RELAYS__", json.dumps(DEFAULT_RELAYS))).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/status":
            self._json(200, BUNKER.snapshot())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not secrets.compare_digest(self.headers.get("X-CSRF", ""), CSRF):
            return self._json(403, {"error": "bad token; reload the page"})
        n = min(int(self.headers.get("Content-Length") or 0), 16384)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
        try:
            if self.path == "/api/unlock":
                if not form.get("password"):
                    raise ValueError("Enter the password.")
                BUNKER.unlock(form["password"], bool(form.get("remember")))
            elif self.path == "/api/setup":
                BUNKER.setup(form.get("mode", ""), form.get("key", "").strip(), form.get("password", ""),
                             parse_relays(form.get("relays")))
            elif self.path == "/api/relays":
                BUNKER.set_relays(parse_relays(form.get("relays")))
            elif self.path == "/api/notify":
                st = load_state()
                st["notify"] = bool(form.get("enabled"))
                save_state(st)
            elif self.path == "/api/notify/test":
                ok, tried, where = NOTIFIER.send("Test from nak bunker: locked reminders will reach you here.")
                if ok == 0:
                    raise ValueError(f"No relay accepted the test message (tried {tried}: {where}).")
                return self._json(200, {"ok": True, "message": f"Sent. {ok}/{tried} relays accepted it ({where})."})
            elif self.path == "/api/client/remove":
                pk = form.get("pubkey", "")
                if not re.fullmatch(r"[0-9a-f]{64}", pk):
                    raise ValueError("bad pubkey")
                BUNKER.remove_client(pk)
            else:
                return self._json(404, {"error": "not found"})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        self._json(200, {"ok": True})


def main():
    os.makedirs(HOME, exist_ok=True)
    signal.signal(signal.SIGTERM, lambda *_: (setattr(BUNKER, "want_running", False), BUNKER.stop(), os._exit(0)))
    BUNKER.start()
    threading.Thread(target=NOTIFIER.loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"nak bunker shim on :{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
