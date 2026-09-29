import base64, os, secrets, uuid as uuidlib
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

import models as m
import engine as eng

ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASS = os.environ["ADMIN_PASS"]
SESSION_SECRET = os.environ["SESSION_SECRET"]
PANEL_DOMAIN = (os.getenv("PANEL_DOMAIN") or os.getenv("RAILWAY_PUBLIC_DOMAIN") or "") \
    .replace("https://", "").replace("http://", "").strip("/")
FRONT_HOST = os.getenv("FRONT_HOST", "www.cloudflare.com:443")
TCP_DOMAIN = os.getenv("TCP_PROXY_DOMAIN", "")   # Railway TCP Proxy domain (for edge mode)
TCP_PORT = os.getenv("TCP_PROXY_PORT", "")       # Railway TCP Proxy public port


@asynccontextmanager
async def lifespan(app):
    m.Base.metadata.create_all(m.engine)
    with m.SessionLocal() as db:
        eng.restart(db)
    eng.start_poller(m.SessionLocal)
    yield
    eng.stop()


app = FastAPI(lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, same_site="lax",
                   https_only=os.getenv("RAILWAY_ENVIRONMENT") is not None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def get_db():
    db = m.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def auth(request: Request):
    if not request.session.get("ok"):
        raise HTTPException(401, "unauthorized")


def host_of(request: Request):
    return PANEL_DOMAIN or request.headers.get("host", "").split(":")[0]


def build_link(c, host):
    ib = c.endpoint
    name = quote(f"{ib.remark}-{c.name}")
    path = quote(ib.path, safe="")
    if ib.kind == "web-http":
        q = (f"encryption=none&security=tls&sni={host}&fp=chrome&type=xhttp&host={host}"
             f"&path={path}&mode={ib.mode}")
        return f"vless://{c.uuid}@{host}:443?{q}#{name}"
    sni = FRONT_HOST.split(":")[0]
    addr = TCP_DOMAIN or host
    port = TCP_PORT or eng.EDGE_PORT
    q = f"encryption=none&security=reality&sni={sni}&fp=chrome&pbk={ib.key_b}&sid={ib.tag_id}"
    if ib.kind == "edge-tcp":
        q += "&type=tcp&flow=xtls-rprx-vision"
    else:
        q += f"&type=xhttp&path={path}&mode={ib.mode}"
    return f"vless://{c.uuid}@{addr}:{port}?{q}#{name}"


# ---------- pages ----------
@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"err": request.query_params.get("err")})


@app.get("/")
def dashboard(request: Request):
    if not request.session.get("ok"):
        return RedirectResponse("/login")
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ok = secrets.compare_digest(username, ADMIN_USER) & secrets.compare_digest(password, ADMIN_PASS)
    if not ok:
        return RedirectResponse("/login?err=1", status_code=303)
    request.session["ok"] = True
    return RedirectResponse("/", status_code=303)


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


# ---------- endpoints ----------
class EndpointIn(BaseModel):
    remark: str
    kind: str
    mode: str = "packet-up"


@app.get("/api/endpoints", dependencies=[Depends(auth)])
def list_endpoints(db=Depends(get_db)):
    return [{"id": i.id, "remark": i.remark, "kind": i.kind, "mode": i.mode,
             "accounts": len(i.clients)} for i in db.query(m.Endpoint).all()]


@app.post("/api/endpoints", dependencies=[Depends(auth)])
def add_endpoint(data: EndpointIn, db=Depends(get_db)):
    if data.kind not in ("web-http", "edge-tcp", "edge-http"):
        raise HTTPException(400, "invalid kind")
    if data.mode not in ("packet-up", "stream-up", "stream-one"):
        raise HTTPException(400, "invalid mode")
    is_edge = data.kind.startswith("edge")
    for i in db.query(m.Endpoint).all():
        if i.kind.startswith("edge") == is_edge:
            raise HTTPException(400, "only one endpoint of this family is supported (one port each)")
    ib = m.Endpoint(remark=data.remark.strip() or "endpoint", kind=data.kind, mode=data.mode,
                   path="/s/" + secrets.token_hex(6) + "/")
    if is_edge:
        ib.key_a, ib.key_b = eng.gen_keys()
        ib.tag_id = secrets.token_hex(8)
    db.add(ib)
    db.commit()
    eng.restart(db)
    return {"id": ib.id}


@app.delete("/api/endpoints/{iid}", dependencies=[Depends(auth)])
def del_endpoint(iid: int, db=Depends(get_db)):
    ib = db.get(m.Endpoint, iid)
    if not ib:
        raise HTTPException(404, "not found")
    db.delete(ib)
    db.commit()
    eng.restart(db)
    return {"ok": True}


# ---------- clients ----------
class AccountIn(BaseModel):
    endpoint_id: int
    name: str
    gb: float = 0      # 0 = unlimited
    days: int = 0      # 0 = never expires


@app.get("/api/accounts", dependencies=[Depends(auth)])
def list_clients(db=Depends(get_db)):
    return [{"id": c.id, "name": c.name, "endpoint": c.endpoint.remark, "used": c.used_bytes or 0,
             "total": c.total_bytes or 0, "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
             "enable": c.enable, "active": eng.is_active(c), "token": c.sub_token}
            for c in db.query(m.Account).all()]


@app.post("/api/accounts", dependencies=[Depends(auth)])
def add_client(data: AccountIn, db=Depends(get_db)):
    if not db.get(m.Endpoint, data.endpoint_id):
        raise HTTPException(400, "endpoint not found")
    c = m.Account(endpoint_id=data.endpoint_id, name=data.name.strip() or "user",
                 uuid=str(uuidlib.uuid4()), sub_token=secrets.token_urlsafe(16),
                 total_bytes=int(data.gb * 1024 ** 3),
                 expiry=datetime.utcnow() + timedelta(days=data.days) if data.days else None)
    db.add(c)
    db.commit()
    eng.restart(db)
    return {"id": c.id}


@app.post("/api/accounts/{cid}/toggle", dependencies=[Depends(auth)])
def toggle_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.enable = not c.enable
    db.commit()
    eng.restart(db)
    return {"enable": c.enable}


@app.post("/api/accounts/{cid}/reset", dependencies=[Depends(auth)])
def reset_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    c.used_bytes = 0
    db.commit()
    eng.restart(db)
    return {"ok": True}


@app.delete("/api/accounts/{cid}", dependencies=[Depends(auth)])
def del_client(cid: int, db=Depends(get_db)):
    c = db.get(m.Account, cid)
    if not c:
        raise HTTPException(404, "not found")
    db.delete(c)
    db.commit()
    eng.restart(db)
    return {"ok": True}


# ---------- subscription ----------
@app.get("/sub/{token}")
def sub(token: str, request: Request, db=Depends(get_db)):
    c = db.query(m.Account).filter_by(sub_token=token).first()
    if not c:
        raise HTTPException(404, "not found")
    link = build_link(c, host_of(request))
    if "text/html" in request.headers.get("accept", ""):
        return templates.TemplateResponse(request, "sub.html", {
            "c": c, "link": link, "active": eng.is_active(c),
            "used": round((c.used_bytes or 0) / 1024 ** 3, 2),
            "total": round((c.total_bytes or 0) / 1024 ** 3, 2),
            "pct": min(100, int((c.used_bytes or 0) * 100 / c.total_bytes)) if c.total_bytes else 0,
            "expiry": c.expiry.strftime("%Y-%m-%d") if c.expiry else "",
        })
    # subscription apps get base64 + usage header
    exp = int(c.expiry.timestamp()) if c.expiry else 0
    hdr = f"upload=0; download={c.used_bytes or 0}; total={c.total_bytes or 0}; expire={exp}"
    body = base64.b64encode(link.encode()).decode()
    return PlainTextResponse(body, headers={"subscription-userinfo": hdr})
