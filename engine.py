import json, os, subprocess, threading
from datetime import datetime
from models import Endpoint, Account

CORE_BIN = os.getenv("CORE_BIN", "/usr/local/bin/appcore")
CONF = "/tmp/core.json"
WEB_PORT = 10000        # internal, reached through Caddy at /s/*
API_PORT = 10085        # internal stats API
EDGE_PORT = int(os.getenv("EDGE_PORT", "4433"))  # expose via Railway TCP Proxy
FRONT_HOST = os.getenv("FRONT_HOST", "www.cloudflare.com:443")

_proc = None
_lock = threading.Lock()
_stop = threading.Event()
_active_ids = set()


def gen_keys():
    """Return (private_key, public_key) from the core binary (old and new output formats)."""
    out = subprocess.check_output([CORE_BIN, "x25519"], text=True)
    vals = [l.split(":", 1)[1].strip() for l in out.splitlines() if ":" in l]
    return vals[0], vals[1]


def is_active(c):
    if not c.enable:
        return False
    if c.expiry and c.expiry < datetime.utcnow():
        return False
    if c.total_bytes and c.used_bytes >= c.total_bytes:
        return False
    return True


def build_config(db):
    inbounds = [{
        "tag": "api", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }]
    for ib in db.query(Endpoint).filter_by(enable=True).all():
        flow = "xtls-rprx-vision" if ib.kind == "edge-tcp" else ""
        clients = []
        for c in ib.clients:
            if is_active(c):
                cl = {"id": c.uuid, "email": f"u{c.id}", "level": 0}
                if flow:
                    cl["flow"] = flow
                clients.append(cl)
        if not clients:
            continue
        stream = {}
        if ib.kind == "web-http":
            stream = {"network": "xhttp", "security": "none",
                      "xhttpSettings": {"path": ib.path, "mode": ib.mode}}
            listen, port = "127.0.0.1", WEB_PORT
        else:
            host = FRONT_HOST.split(":")[0]
            stream = {
                "network": "tcp" if ib.kind == "edge-tcp" else "xhttp",
                "security": "reality",
                "realitySettings": {
                    "show": False, "dest": FRONT_HOST, "serverNames": [host],
                    "privateKey": ib.key_a, "shortIds": [ib.tag_id],
                },
            }
            if ib.kind == "edge-http":
                stream["xhttpSettings"] = {"path": ib.path, "mode": ib.mode}
            listen, port = "0.0.0.0", EDGE_PORT
        inbounds.append({
            "tag": f"in{ib.id}", "listen": listen, "port": port, "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": stream,
        })
    return {
        "log": {"loglevel": "warning"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]},
    }


def restart(db):
    global _proc, _active_ids
    with _lock:
        cfg = build_config(db)
        _active_ids = {c.id for c in db.query(Account).all() if is_active(c)}
        with open(CONF, "w") as f:
            json.dump(cfg, f)
        if _proc and _proc.poll() is None:
            _proc.terminate()
            try:
                _proc.wait(5)
            except subprocess.TimeoutExpired:
                _proc.kill()
        _proc = subprocess.Popen([CORE_BIN, "run", "-c", CONF])


def _poll(SessionLocal):
    while not _stop.is_set():
        _stop.wait(30)
        try:
            out = subprocess.run(
                [CORE_BIN, "api", "statsquery", f"--server=127.0.0.1:{API_PORT}", "-reset"],
                capture_output=True, text=True, timeout=15).stdout
            stats = json.loads(out).get("stat", []) if out.strip() else []
            with SessionLocal() as db:
                for s in stats:
                    p = s["name"].split(">>>")
                    if len(p) >= 4 and p[0] == "user":
                        c = db.get(Account, int(p[1][1:]))
                        if c:
                            c.used_bytes = (c.used_bytes or 0) + int(s.get("value", 0))
                db.commit()
                cur = {c.id for c in db.query(Account).all() if is_active(c)}
                if cur != _active_ids:
                    restart(db)
        except Exception as e:  # keep the poller alive
            print("poll error:", e, flush=True)


def start_poller(SessionLocal):
    threading.Thread(target=_poll, args=(SessionLocal,), daemon=True).start()


def stop():
    _stop.set()
    if _proc and _proc.poll() is None:
        _proc.terminate()
