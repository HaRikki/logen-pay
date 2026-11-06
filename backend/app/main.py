import os, hmac, hashlib, secrets, json, time, datetime as dt
import httpx
from collections import defaultdict
from cryptography.fernet import Fernet
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import BaseModel, Field
from sqlalchemy import (create_engine, String, Integer, Boolean, DateTime, Text,
                        Numeric, ForeignKey, select)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

E = os.environ
DB = E.get("DATABASE_URL", "sqlite:///./dev.db").replace("postgres://", "postgresql://", 1)
SECRET = E.get("SECRET_KEY", "dev-secret")
PROVIDER = E.get("PROVIDER_BASE_URL", "https://khqrpay.site").rstrip("/")
CHECK_URL = E.get("PROVIDER_CHECK_URL", "")
PUBLIC = E.get("PUBLIC_BASE_URL", "").rstrip("/")
CHECKOUT = (E.get("CHECKOUT_BASE_URL") or PUBLIC).rstrip("/")
RATE = int(E.get("RATE_LIMIT_PER_MIN", "60"))
ORIGINS = [o for o in E.get("ALLOWED_ORIGINS", "").split(",") if o]
fernet = Fernet(E["FERNET_KEY"].encode()) if E.get("FERNET_KEY") else None
signer = URLSafeTimedSerializer(SECRET)
now = lambda: dt.datetime.now(dt.timezone.utc)

class Base(DeclarativeBase): pass
def col(t, **k): return mapped_column(t, **k)
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = col(Integer, primary_key=True)
    email: Mapped[str] = col(String, unique=True, index=True)
    pw: Mapped[str] = col(String)
    status: Mapped[str] = col(String, default="active")
    is_admin: Mapped[bool] = col(Boolean, default=False)
    created: Mapped[dt.datetime] = col(DateTime(timezone=True), default=now)
class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = col(Integer, primary_key=True)
    user_id: Mapped[int] = col(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = col(String)
    prefix: Mapped[str] = col(String)
    hash: Mapped[str] = col(String, unique=True, index=True)
    revoked: Mapped[bool] = col(Boolean, default=False)
    last_used: Mapped[dt.datetime | None] = col(DateTime(timezone=True), nullable=True)
    requests: Mapped[int] = col(Integer, default=0)
    created: Mapped[dt.datetime] = col(DateTime(timezone=True), default=now)
class Merchant(Base):  # ABA merchants and Bakong accounts, split by kind
    __tablename__ = "merchants"
    id: Mapped[int] = col(Integer, primary_key=True)
    user_id: Mapped[int] = col(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = col(String)  # aba | bakong
    name: Mapped[str] = col(String)
    provider_key_enc: Mapped[str] = col(Text)  # Fernet-encrypted, never returned
    enabled: Mapped[bool] = col(Boolean, default=True)
class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = col(Integer, primary_key=True)
    order_id: Mapped[str] = col(String, unique=True, index=True)
    user_id: Mapped[int] = col(ForeignKey("users.id"), index=True)
    merchant_id: Mapped[int] = col(ForeignKey("merchants.id"))
    kind: Mapped[str] = col(String)
    amount: Mapped[float] = col(Numeric(18, 2))
    currency: Mapped[str] = col(String, default="USD")
    status: Mapped[str] = col(String, default="pending")
    provider_ref: Mapped[str | None] = col(String, nullable=True)
    raw: Mapped[str] = col(Text, default="{}")
    idem: Mapped[str | None] = col(String, nullable=True, index=True)
    created: Mapped[dt.datetime] = col(DateTime(timezone=True), default=now)
    expires: Mapped[dt.datetime] = col(DateTime(timezone=True))
class Webhook(Base):
    __tablename__ = "webhooks"
    id: Mapped[int] = col(Integer, primary_key=True)
    user_id: Mapped[int] = col(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = col(String)
    secret: Mapped[str] = col(String)
    enabled: Mapped[bool] = col(Boolean, default=True)
class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[int] = col(Integer, primary_key=True)
    webhook_id: Mapped[int] = col(ForeignKey("webhooks.id", ondelete="CASCADE"), index=True)
    event: Mapped[str] = col(String)
    code: Mapped[int | None] = col(Integer, nullable=True)
    ok: Mapped[bool] = col(Boolean, default=False)
    created: Mapped[dt.datetime] = col(DateTime(timezone=True), default=now)

engine = create_engine(DB, pool_pre_ping=True)
Session_ = sessionmaker(engine, expire_on_commit=False)
def db():
    with Session_() as s: yield s

app = FastAPI(title="Logen KHPay")
if ORIGINS:
    app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])
@app.on_event("startup")
def startup(): Base.metadata.create_all(engine)  # replace with Alembic revisions in prod

def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(16)
    return f"{salt}${hashlib.pbkdf2_hmac('sha256', p.encode(), salt.encode(), 310000).hex()}"
def check_pw(p, stored):
    salt, _ = stored.split("$")
    return hmac.compare_digest(hash_pw(p, salt), stored)
def enc(s):
    if not fernet: raise HTTPException(500, "FERNET_KEY not configured")
    return fernet.encrypt(s.encode()).decode()
def dec(s): return fernet.decrypt(s.encode()).decode()
_hits = defaultdict(list)
def limit(k):
    t = time.time(); _hits[k] = [x for x in _hits[k] if t - x < 60]
    if len(_hits[k]) >= RATE: raise HTTPException(429, "rate_limited")
    _hits[k].append(t)

def session_user(req: Request, s: Session = Depends(db)) -> User:
    try: uid = signer.loads(req.cookies.get("sid", ""), max_age=60 * 60 * 24 * 30)
    except BadSignature: raise HTTPException(401, "not_authenticated")
    if req.method != "GET" and "application/json" not in req.headers.get("content-type", ""):
        raise HTTPException(415, "json_required")  # basic CSRF guard (+SameSite cookie)
    u = s.get(User, uid)
    if not u or u.status != "active": raise HTTPException(401, "not_authenticated")
    return u
def api_user(req: Request, s: Session = Depends(db)) -> User:
    h = req.headers.get("authorization", "")
    if not h.startswith("Bearer sk_live_"): raise HTTPException(401, "invalid_api_key")
    k = s.scalar(select(ApiKey).where(ApiKey.hash == hashlib.sha256(h[7:].encode()).hexdigest()))
    if not k or k.revoked: raise HTTPException(401, "invalid_api_key")
    u = s.get(User, k.user_id)
    if u.status != "active": raise HTTPException(403, "account_suspended")
    limit(f"k{k.id}"); k.last_used = now(); k.requests += 1; s.commit()
    return u

class Cred(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(min_length=8, max_length=128)
def login_cookie(resp, u):
    resp.set_cookie("sid", signer.dumps(u.id), httponly=True, secure=PUBLIC.startswith("https"),
                    samesite="lax", max_age=60 * 60 * 24 * 30)
@app.get("/health")
def health(): return {"status": "ok"}
@app.post("/auth/register")
def register(c: Cred, resp: Response, s: Session = Depends(db)):
    email = c.email.lower()
    if s.scalar(select(User).where(User.email == email)): raise HTTPException(409, "email_taken")
    u = User(email=email, pw=hash_pw(c.password), is_admin=(email == E.get("ADMIN_EMAIL", "").lower()))
    s.add(u); s.commit(); login_cookie(resp, u); return {"id": u.id, "email": u.email}
@app.post("/auth/login")
def login(c: Cred, resp: Response, s: Session = Depends(db)):
    limit("login:" + c.email.lower())
    u = s.scalar(select(User).where(User.email == c.email.lower()))
    if not u or not check_pw(c.password, u.pw) or u.status != "active": raise HTTPException(401, "bad_credentials")
    login_cookie(resp, u); return {"id": u.id, "email": u.email}
@app.post("/auth/logout")
def logout(resp: Response): resp.delete_cookie("sid"); return {"ok": True}
@app.get("/auth/me")
def me(u: User = Depends(session_user)): return {"id": u.id, "email": u.email, "is_admin": u.is_admin}

class KeyIn(BaseModel): name: str = Field(max_length=60)
@app.post("/dashboard/keys")
def create_key(b: KeyIn, u: User = Depends(session_user), s: Session = Depends(db)):
    secret = "sk_live_" + secrets.token_urlsafe(32)
    s.add(ApiKey(user_id=u.id, name=b.name, prefix=secret[:12], hash=hashlib.sha256(secret.encode()).hexdigest()))
    s.commit(); return {"secret": secret, "note": "Shown once. Store it now."}
@app.get("/dashboard/keys")
def list_keys(u: User = Depends(session_user), s: Session = Depends(db)):
    return [{"id": k.id, "name": k.name, "prefix": k.prefix, "revoked": k.revoked,
             "last_used": k.last_used, "requests": k.requests, "created": k.created}
            for k in s.scalars(select(ApiKey).where(ApiKey.user_id == u.id))]
@app.post("/dashboard/keys/{kid}/revoke")
def revoke_key(kid: int, u: User = Depends(session_user), s: Session = Depends(db)):
    k = s.get(ApiKey, kid)
    if not k or k.user_id != u.id: raise HTTPException(404, "not_found")
    k.revoked = True; s.commit(); return {"ok": True}

class MerchantIn(BaseModel):
    kind: str = Field(pattern="^(aba|bakong)$"); name: str; provider_key: str
@app.post("/dashboard/merchants")
def add_merchant(b: MerchantIn, u: User = Depends(session_user), s: Session = Depends(db)):
    m = Merchant(user_id=u.id, kind=b.kind, name=b.name, provider_key_enc=enc(b.provider_key))
    s.add(m); s.commit(); return {"id": m.id, "kind": m.kind, "name": m.name}
@app.get("/dashboard/merchants")
def list_merchants(u: User = Depends(session_user), s: Session = Depends(db)):
    return [{"id": m.id, "kind": m.kind, "name": m.name, "enabled": m.enabled}
            for m in s.scalars(select(Merchant).where(Merchant.user_id == u.id))]
@app.delete("/dashboard/merchants/{mid}")
def del_merchant(mid: int, u: User = Depends(session_user), s: Session = Depends(db)):
    m = s.get(Merchant, mid)
    if not m or m.user_id != u.id: raise HTTPException(404, "not_found")
    s.delete(m); s.commit(); return {"ok": True}

class HookIn(BaseModel): url: str = Field(pattern=r"^https://")
@app.post("/dashboard/webhooks")
def add_hook(b: HookIn, u: User = Depends(session_user), s: Session = Depends(db)):
    w = Webhook(user_id=u.id, url=b.url, secret="whsec_" + secrets.token_urlsafe(24))
    s.add(w); s.commit(); return {"id": w.id, "url": w.url, "secret": w.secret}
@app.get("/dashboard/webhooks")
def list_hooks(u: User = Depends(session_user), s: Session = Depends(db)):
    return [{"id": w.id, "url": w.url, "enabled": w.enabled} for w in s.scalars(select(Webhook).where(Webhook.user_id == u.id))]
def fire(s: Session, p: Payment, event: str):
    body = json.dumps({"event": event, "order_id": p.order_id, "amount": float(p.amount),
                       "currency": p.currency, "status": p.status}, separators=(",", ":"))
    for w in s.scalars(select(Webhook).where(Webhook.user_id == p.user_id, Webhook.enabled)):
        sig = hmac.new(w.secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        try:
            r = httpx.post(w.url, content=body, timeout=10,
                           headers={"Content-Type": "application/json", "X-KHPay-Signature": sig})
            code, ok = r.status_code, r.is_success
        except Exception: code, ok = None, False
        s.add(WebhookDelivery(webhook_id=w.id, event=event, code=code, ok=ok))
    s.commit()

class PayIn(BaseModel): amount: float = Field(gt=0, le=100000)
def view(p: Payment):
    return {"order_id": p.order_id, "kind": p.kind, "amount": float(p.amount), "currency": p.currency,
            "status": p.status, "created": p.created, "expires": p.expires,
            "checkout_url": f"{CHECKOUT}/pay/{p.order_id}", "provider": json.loads(p.raw)}
def create(kind, b: PayIn, req: Request, u: User, s: Session):
    idem = req.headers.get("idempotency-key")
    if idem:
        old = s.scalar(select(Payment).where(Payment.user_id == u.id, Payment.idem == idem))
        if old: return view(old)
    m = s.scalar(select(Merchant).where(Merchant.user_id == u.id, Merchant.kind == kind, Merchant.enabled))
    if not m: raise HTTPException(400, f"no_{kind}_merchant_configured")
    r = httpx.post(f"{PROVIDER}/api/v1/{kind}/create", json={"amount": b.amount},
                   headers={"Authorization": f"Bearer {dec(m.provider_key_enc)}"}, timeout=20)
    if not r.is_success: raise HTTPException(502, f"provider_error_{r.status_code}")
    raw = r.json()
    d = raw.get("data", raw) if isinstance(raw, dict) else {}
    ref = next((str(d[k]) for k in ("order_id", "id", "transaction_id", "md5") if k in d), None)
    p = Payment(order_id="ord_" + secrets.token_urlsafe(12), user_id=u.id, merchant_id=m.id, kind=kind,
                amount=b.amount, provider_ref=ref, raw=json.dumps(raw), idem=idem,
                expires=now() + dt.timedelta(minutes=10))
    s.add(p); s.commit(); fire(s, p, "payment.pending"); return view(p)
@app.post("/api/v1/aba/create")
def aba(b: PayIn, req: Request, u: User = Depends(api_user), s: Session = Depends(db)): return create("aba", b, req, u, s)
@app.post("/api/v1/bakong/create")
def bakong(b: PayIn, req: Request, u: User = Depends(api_user), s: Session = Depends(db)): return create("bakong", b, req, u, s)

def refresh(p: Payment, s: Session):
    if p.status != "pending": return p
    if not CHECK_URL:
        raise HTTPException(501, "PROVIDER_CHECK_URL not configured (see README setup requirement)")
    m = s.get(Merchant, p.merchant_id)
    r = httpx.get(CHECK_URL.format(ref=p.provider_ref), timeout=20,
                  headers={"Authorization": f"Bearer {dec(m.provider_key_enc)}"})
    raw = r.json() if r.is_success else {}
    d = raw.get("data", raw) if isinstance(raw, dict) else {}
    if str(d.get("status", "")).lower() in ("paid", "success", "completed"):
        p.status = "paid"; s.commit(); fire(s, p, "payment.paid")
    elif now() > p.expires:
        p.status = "expired"; s.commit(); fire(s, p, "payment.expired")
    return p
@app.get("/api/v1/payment")
def get_payment(id: str, u: User = Depends(api_user), s: Session = Depends(db)):
    p = s.scalar(select(Payment).where(Payment.order_id == id))
    if not p or p.user_id != u.id: raise HTTPException(404, "not_found")  # ownership check
    return view(refresh(p, s))
@app.get("/api/v1/payments")
def payments(u: User = Depends(api_user), s: Session = Depends(db)):
    return [view(p) for p in s.scalars(select(Payment).where(Payment.user_id == u.id).order_by(Payment.id.desc()).limit(100))]

@app.get("/pay/{order_id}/status")
def pay_status(order_id: str, s: Session = Depends(db)):
    p = s.scalar(select(Payment).where(Payment.order_id == order_id))
    if not p: raise HTTPException(404, "not_found")
    try: refresh(p, s)
    except HTTPException: pass
    raw = json.loads(p.raw); d = raw.get("data", raw) if isinstance(raw, dict) else {}
    return {"status": p.status, "amount": float(p.amount), "currency": p.currency,
            "expires": p.expires, "qr": d.get("qr") or d.get("qr_string") or d.get("khqr"),
            "qr_image": d.get("qr_image") or d.get("qrImage"),
            "deeplink": d.get("deeplink") or d.get("abapay_deeplink")}
PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Logen KHPay</title><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>body{margin:0;font-family:system-ui;background:#0a1628;color:#fff;display:grid;place-items:center;min-height:100vh}
.c{background:#fff;color:#0a1628;border-radius:20px;padding:28px;width:min(92vw,360px);text-align:center}
h1{color:#087FA5;font-size:20px;margin:0 0 8px}#q{display:grid;place-items:center;margin:16px 0}
.b{display:inline-block;background:#087FA5;color:#fff;padding:10px 18px;border-radius:10px;text-decoration:none}</style>
<div class=c><h1>Logen KHPay</h1><div id=a></div><div id=q></div><div id=s>Loading...</div><div id=t></div><p id=d></p></div>
<script>const id=location.pathname.split('/').pop();let ex;
async function tick(){const r=await (await fetch('/pay/'+id+'/status')).json();
a.textContent=r.amount+' '+r.currency;ex=new Date(r.expires);
if(r.status=='paid'){s.textContent='Payment successful';q.innerHTML='';return}
if(r.status=='expired'||new Date()>ex){s.textContent='Expired - create a new QR';q.innerHTML='';return}
if(!q.hasChildNodes()){if(r.qr_image){q.innerHTML='<img width=220 src="'+r.qr_image+'">'}else if(r.qr){new QRCode(q,{text:r.qr,width:220,height:220})}}
if(r.deeplink)d.innerHTML='<a class=b href="'+r.deeplink+'">Open ABA Mobile</a>';
const m=Math.max(0,Math.floor((ex-new Date())/1000));t.textContent=Math.floor(m/60)+':'+String(m%60).padStart(2,'0');
s.textContent='Waiting for payment...';setTimeout(tick,3000)}tick()</script>"""
@app.get("/pay/{order_id}", response_class=HTMLResponse)
def pay_page(order_id: str): return PAGE
