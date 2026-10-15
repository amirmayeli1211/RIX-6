from __future__ import annotations
import asyncio, html, json, logging, os, secrets, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from database import SessionLocal, engine, get_db, init_db
from models import Admin, AuditLog, Client, Node, utcnow
from security import password_hash, verify_password, encrypt_secret, decrypt_secret, new_token, token_hash, csrf_token, constant_time_equal
from protocols import PROTOCOLS, ConfigError, build_config, format_bytes, safe_host
from railway_xray import LOCAL_NODE_MARKER, SUPPORTED_PROTOCOLS, WEBSOCKET_PATHS, runtime

ROOT = Path(__file__).resolve().parent
logger = logging.getLogger("rix_storm")
APP_NAME = os.getenv("APP_NAME", "RIX STORM PANEL 2.5")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
APP_ENV = os.getenv("APP_ENV", "development").lower()
def _load_session_secret() -> str:
    configured = os.getenv("SECRET_KEY", "").strip()
    if configured:
        return configured
    data_dir = Path(os.getenv("DATA_DIR", "/data" if os.getenv("APP_ENV", "development").lower() == "production" else "."))
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / ".rix-session-secret"
    if not path.exists():
        generated = secrets.token_urlsafe(64).encode("ascii")
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(generated)
        except FileExistsError:
            pass
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path.read_text(encoding="ascii").strip()


SECRET_KEY = _load_session_secret()
SESSION_AGE = int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))
templates = Jinja2Templates(directory=str(ROOT))
_expiry_task: asyncio.Task | None = None

async def _expiry_sweeper() -> None:
    # Disable expired users and rebuild the one local Xray config. Usage is not live-metered yet.
    while True:
        await asyncio.sleep(60)
        with SessionLocal() as db:
            now = utcnow()
            due = db.scalars(select(Client).where(Client.enabled.is_(True),
                ((Client.expires_at.is_not(None) & (Client.expires_at <= now)) |
                 ((Client.quota_bytes > 0) & (Client.used_bytes >= Client.quota_bytes))))).all()
            if not due:
                continue
            for client in due:
                client.enabled = False
                client.updated_at = utcnow()
                db.add(AuditLog(admin_id=None, action="client.auto_disable", entity="client",
                                entity_id=str(client.id), details="expiry/quota threshold reached"))
            try:
                db.flush()
                local_node = db.scalar(select(Node).where(Node.agent_url == LOCAL_NODE_MARKER).limit(1))
                if local_node:
                    runtime.sync(db, local_node.id)
                db.commit()
            except Exception:
                db.rollback()

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _expiry_task
    if APP_ENV == "production":
        if len(SECRET_KEY) < 40 or SECRET_KEY.startswith("local-dev"):
            raise RuntimeError("برای production یک SECRET_KEY تصادفی حداقل ۴۰ کاراکتری تنظیم کن.")
        if not os.getenv("ADMIN_USERNAME") or len(os.getenv("ADMIN_PASSWORD", "")) < 16:
            raise RuntimeError("ADMIN_USERNAME و ADMIN_PASSWORD حداقل ۱۶ کاراکتری را تنظیم کن.")
    init_db()
    username, password = os.getenv("ADMIN_USERNAME", "").strip(), os.getenv("ADMIN_PASSWORD", "")
    if username and password:
        with SessionLocal() as db:
            if not db.scalar(select(Admin).where(Admin.username == username)):
                db.add(Admin(username=username, password_hash=password_hash(password), active=True))
                db.commit()
    # Xray is part of this Railway container; no remote VPS or Agent is used.
    runtime.start_empty()
    # Restore saved users immediately after redeploy when Railway's public domain is known.
    # On custom-domain-only setups, the first authenticated dashboard visit performs this sync.
    if PUBLIC_BASE_URL or os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip():
        try:
            with SessionLocal() as db:
                node = _ensure_railway_node(db, None)
                db.commit()
                runtime.sync(db, node.id)
        except (ValueError, RuntimeError) as exc:
            logger.warning("Automatic Xray restore will retry on the dashboard: %s", exc)
    _expiry_task = asyncio.create_task(_expiry_sweeper())
    try:
        yield
    finally:
        if _expiry_task and not _expiry_task.done():
            _expiry_task.cancel()
            try:
                await _expiry_task
            except asyncio.CancelledError:
                pass
        _expiry_task = None
        runtime.shutdown()


app = FastAPI(title=APP_NAME, docs_url=None if APP_ENV == "production" else "/docs", redoc_url=None, lifespan=lifespan)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, session_cookie="rix_storm_session", max_age=SESSION_AGE,
                   same_site="lax", https_only=APP_ENV == "production")

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.url.path.startswith(("/s/", "/sub/")):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response

@app.exception_handler(StarletteHTTPException)
async def friendly_http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code in (303, 307, 308) and exc.headers and exc.headers.get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=exc.status_code)
    if request.url.path.startswith(("/s/", "/sub/")) and exc.status_code in (403, 404, 410):
        safe_detail = html.escape(str(exc.detail))
        return HTMLResponse(f"<!doctype html><html lang='fa' dir='rtl'><meta charset='utf-8'><title>اشتراک در دسترس نیست</title><body style='font:16px sans-serif;max-width:620px;margin:10vh auto;padding:24px;background:#111820;color:#edf3f7;border-radius:20px'><h2>این اشتراک در دسترس نیست</h2><p>{safe_detail}</p><a style='color:#85dfb5' href='/'>بازگشت به پنل</a></body></html>", status_code=exc.status_code, headers={"Cache-Control": "no-store"})
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail}, headers=exc.headers or {})

@app.get("/health", include_in_schema=False)
def health():
    """Platform health probe; no credentials or user details are exposed."""
    state = runtime.status()
    return {"ok": True, "service": "rix-storm-panel", "version": "2.5",
            "xray": state["state"], "configured_users": state["configured_users"]}

@app.get("/app.css", include_in_schema=False)
def css():
    return FileResponse(ROOT / "app.css", media_type="text/css", headers={"Cache-Control": "public, max-age=300"})

@app.get("/app.js", include_in_schema=False)
def javascript():
    return FileResponse(ROOT / "app.js", media_type="application/javascript", headers={"Cache-Control": "public, max-age=300"})

def _base_url(request: Request | None = None) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
    if railway_domain:
        if "://" in railway_domain:
            return railway_domain.rstrip("/")
        return "https://" + railway_domain.strip("/")
    if request is None:
        return ""
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",", 1)[0].strip()
    if APP_ENV == "production" and host:
        return "https://" + host
    return str(request.base_url).rstrip("/")


def _railway_host(request: Request | None) -> str:
    base = _base_url(request)
    if not base:
        raise ValueError("دامنهٔ عمومی Railway هنوز پیدا نشده است؛ Public Domain سرویس را فعال کن.")
    parsed = urlsplit(base if "://" in base else "https://" + base)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("دامنهٔ عمومی Railway پیدا نشد؛ برای سرویس Public Domain بساز.")
    return safe_host(host)


def _railway_config_for_client(node: Node, client: Client, credential: str) -> str:
    protocol = client.protocol
    if protocol not in SUPPORTED_PROTOCOLS:
        return ""
    path = WEBSOCKET_PATHS[protocol]
    return build_config(node, protocol, "ws", "tls", credential, 443, client.name,
                        node.host, path, "", "", "chacha20-ietf-poly1305")


def _ensure_railway_node(db: Session, request: Request | None) -> Node:
    """Create/update one hidden local runtime record and migrate prior users to it."""
    host = _railway_host(request)
    node = db.scalar(select(Node).where(Node.agent_url == LOCAL_NODE_MARKER).limit(1))
    if node is None:
        node = Node(
            name="Railway · Xray داخلی", host=host, proxy_ip=None,
            port_start=20000, port_end=65535, agent_url=LOCAL_NODE_MARKER,
            agent_token_encrypted=encrypt_secret(new_token(48)), tls_sni=host,
            tls_cert_path="railway-edge-managed", tls_key_path="railway-edge-managed",
            reality_sni=None, reality_public_key=None, reality_short_id=None,
            enabled=True, notes="Runtime داخلی؛ مدیریت‌شده توسط همین Railway service.",
        )
        db.add(node)
        db.flush()
    host_changed = node.host != host
    node.name = "Railway · Xray داخلی"
    node.host = host
    node.proxy_ip = None
    node.tls_sni = host
    node.tls_cert_path = "railway-edge-managed"
    node.tls_key_path = "railway-edge-managed"
    node.enabled = True
    db.flush()

    existing_local = db.scalars(select(Client).where(Client.node_id == node.id).order_by(Client.id)).all()
    used_ports = {int(c.port) for c in existing_local if c.port}
    migrating = db.scalars(select(Client).where(Client.node_id != node.id).order_by(Client.id)).all()
    for client in migrating:
        client.node_id = node.id
        port = 20000
        while port in used_ports:
            port += 1
        if port > node.port_end:
            raise ValueError("ظرفیت داخلی کاربرها تمام شده است.")
        client.port = port
        used_ports.add(port)

    db.flush()
    if host_changed or migrating:
        local_clients = db.scalars(select(Client).where(Client.node_id == node.id).order_by(Client.id)).all()
        for client in local_clients:
            if client.protocol not in SUPPORTED_PROTOCOLS:
                client.enabled = False
                client.config_encrypted = encrypt_secret(
                    "این پروتکل در ورودی HTTP/WebSocket عمومی Railway قابل ارائه نیست. برای جلوگیری از ساخت کانفیگ اشتباه، این حساب غیرفعال شد."
                )
                continue
            try:
                credential = decrypt_secret(client.credential_encrypted)
                client.transport = "ws"
                client.security = "tls"
                client.config_encrypted = encrypt_secret(_railway_config_for_client(node, client, credential))
                client.inbound_json_encrypted = encrypt_secret(json.dumps({
                    "runtime": "railway", "protocol": client.protocol,
                    "path": WEBSOCKET_PATHS[client.protocol]}, separators=(",", ":")))
            except Exception:
                client.enabled = False
                client.config_encrypted = encrypt_secret(
                    "اطلاعات رمزگذاری‌شدهٔ این کاربر قابل بازخوانی نیست؛ DATA_ENCRYPTION_KEY قبلی را در Railway بازیابی کن."
                )
    db.flush()
    return node


def _flash(request: Request, message: str, kind: str = "success") -> None:
    request.session["flash"] = {"message": message, "kind": kind}

def _render(request: Request, template: str, **ctx: Any) -> HTMLResponse:
    flash = request.session.pop("flash", None)
    context = {"request": request, "app_name": APP_NAME, "csrf": csrf_token(request.session), "flash": flash,
               "admin": None, "nav": "", "page_title": APP_NAME, "protocols": {p: PROTOCOLS[p] for p in SUPPORTED_PROTOCOLS},
               "transports": ["ws"], "securities": ["tls"], "ciphers": [],
               "base_url": _base_url(request)}
    context.update(ctx)
    return templates.TemplateResponse(request=request, name=template, context=context)

async def _form(request: Request) -> dict[str, str]:
    form = await request.form()
    return {str(k): str(v) for k, v in form.items()}

async def _verify_csrf(request: Request) -> dict[str, str]:
    data = await _form(request)
    sent, expected = data.get("csrf", ""), request.session.get("_csrf", "")
    if not sent or not expected or not constant_time_equal(sent, expected):
        raise HTTPException(status_code=403, detail="درخواست نامعتبر یا منقضی شده است؛ صفحه را تازه‌سازی کن.")
    return data

def _admin(request: Request, db: Session) -> Admin:
    admin_id = request.session.get("admin_id")
    if not admin_id:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    admin = db.get(Admin, int(admin_id))
    if not admin or not admin.active:
        request.session.clear()
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return admin

def _audit(db: Session, admin: Admin | None, action: str, entity: str, entity_id: object | None, details: str = "") -> None:
    db.add(AuditLog(admin_id=admin.id if admin else None, action=action, entity=entity,
                    entity_id=str(entity_id) if entity_id is not None else None, details=details[:500]))

def _required(data: dict[str, str], key: str, label: str, max_len: int = 255) -> str:
    value = data.get(key, "").strip()
    if not value: raise ValueError(f"{label} الزامی است.")
    if len(value) > max_len: raise ValueError(f"{label} بیش از حد طولانی است.")
    return value

def _gib_to_bytes(value: str, label: str) -> int:
    try:
        amount = float(value or "0")
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} باید عددی باشد.") from exc
    if amount < 0 or amount > 1_000_000:
        raise ValueError(f"{label} خارج از محدوده مجاز است.")
    return int(amount * (1024 ** 3))

def _next_port(db: Session, node: Node) -> int:
    used = set(db.scalars(select(Client.port).where(Client.node_id == node.id)).all())
    for port in range(node.port_start, node.port_end + 1):
        if port not in used: return port
    raise ValueError("تمام پورت‌های این نود مصرف شده‌اند؛ بازه پورت را بزرگ‌تر کن.")

def _client_status(client: Client) -> tuple[str, str]:
    if not client.enabled: return "غیرفعال", "muted"
    if client.expires_at and client.expires_at <= utcnow(): return "منقضی‌شده", "danger"
    if client.quota_bytes and client.used_bytes >= client.quota_bytes: return "حجم تمام‌شده", "danger"
    return "فعال", "success"

def _share_url(request: Request, client: Client) -> str:
    return f"{_base_url(request)}/s/{decrypt_secret(client.subscription_token_encrypted)}"

def _client_state(client: Client, node: Node) -> dict[str, Any]:
    status, kind = _client_status(client)
    remaining = max(0, client.quota_bytes - client.used_bytes) if client.quota_bytes else None
    usage = min(100, round(client.used_bytes / client.quota_bytes * 100)) if client.quota_bytes else 0
    days_left = max(0, int((client.expires_at - utcnow()).total_seconds() // 86400)) if client.expires_at else None
    config = decrypt_secret(client.config_encrypted)
    return {"status": status, "status_kind": kind, "config_text": config,
            "remaining_bytes": remaining, "usage_percent": usage, "days_left": days_left,
            "quota_text": "نامحدود" if not client.quota_bytes else format_bytes(client.quota_bytes),
            "used_text": format_bytes(client.used_bytes),
            "remaining_text": "نامحدود" if remaining is None else format_bytes(remaining),
            "expires_text": client.expires_at.strftime("%Y/%m/%d") if client.expires_at else "بدون انقضا",
            "node_endpoint": f"{node.host}:443"}

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    admin = _admin(request, db)
    try:
        node = _ensure_railway_node(db, request)
        db.commit()
        try:
            runtime.sync(db, node.id)
        except RuntimeError:
            # Render the home page even if Xray reports a deployment/runtime error.
            pass
    except (ValueError, RuntimeError):
        db.rollback()
        node = db.scalar(select(Node).where(Node.agent_url == LOCAL_NODE_MARKER).limit(1))
    total_clients = db.scalar(select(func.count(Client.id))) or 0
    current = utcnow()
    active = db.scalar(select(func.count(Client.id)).where(Client.enabled.is_(True),
        ((Client.expires_at.is_(None)) | (Client.expires_at > current)),
        ((Client.quota_bytes == 0) | (Client.used_bytes < Client.quota_bytes)))) or 0
    used = db.scalar(select(func.sum(Client.used_bytes))) or 0
    clients = db.scalars(select(Client).order_by(desc(Client.created_at)).limit(7)).all()
    rows = []
    for client in clients:
        client_node = db.get(Node, client.node_id)
        status, kind = _client_status(client)
        rows.append({"client": client, "node": client_node, "status": status, "status_kind": kind,
                     "share_url": _share_url(request, client)})
    xray = runtime.status()
    base_url = _base_url(request)
    info = {
        "name": "Railway · Xray داخلی",
        "host": node.host if node else (os.getenv("RAILWAY_PUBLIC_DOMAIN") or "دامنهٔ Railway هنوز تعیین نشده"),
        "url": base_url,
        "port": "443",
        "transport": "WebSocket امن (WSS) / TLS لبهٔ Railway",
        "protocols": "VLESS · VMess · Trojan",
        "status": xray,
        "storage_path": os.getenv("DATA_DIR", "/data"),
    }
    return _render(request, "dashboard.html", admin=admin, nav="dashboard", page_title="نمای کلی",
                   client_count=total_clients, active_count=active, node_count=1 if node else 0,
                   used_text=format_bytes(used), clients=rows, server_info=info)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("admin_id"): return RedirectResponse("/", status_code=303)
    return _render(request, "login.html", hide_shell=True, page_title="ورود مدیر")

@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await _verify_csrf(request)
    username, password = data.get("username", "").strip(), data.get("password", "")
    admin = db.scalar(select(Admin).where(Admin.username == username))
    if not admin or not admin.active or not verify_password(password, admin.password_hash):
        _flash(request, "نام کاربری یا رمز عبور صحیح نیست.", "error")
        return RedirectResponse("/login", status_code=303)
    request.session.clear()
    request.session["admin_id"] = admin.id
    csrf_token(request.session)
    _audit(db, admin, "auth.login", "admin", admin.id, "ورود موفق")
    db.commit()
    return RedirectResponse("/", status_code=303)

@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    await _verify_csrf(request)
    admin_id = request.session.get("admin_id")
    admin = db.get(Admin, int(admin_id)) if admin_id else None
    if admin: _audit(db, admin, "auth.logout", "admin", admin.id)
    db.commit(); request.session.clear()
    return RedirectResponse("/login", status_code=303)

@app.get("/nodes", include_in_schema=False)
def legacy_nodes_redirect():
    # Keep old bookmarks working while the node-management UI remains removed.
    return RedirectResponse("/", status_code=303)

@app.get("/clients", response_class=HTMLResponse)
def clients_page(request: Request, db: Session = Depends(get_db)):
    admin = _admin(request, db)
    node = _ensure_railway_node(db, request)
    db.commit()
    try:
        runtime.sync(db, node.id)
    except RuntimeError:
        pass
    clients = db.scalars(select(Client).order_by(desc(Client.created_at))).all()
    rows = []
    for client in clients:
        client_node = db.get(Node, client.node_id)
        status, kind = _client_status(client)
        try:
            config = decrypt_secret(client.config_encrypted)
        except Exception:
            config = "اطلاعات کانفیگ قابل بازخوانی نیست."
        rows.append({"client": client, "node": client_node, "status": status, "status_kind": kind,
                     "share_url": _share_url(request, client), "config": config})
    return _render(request, "clients.html", admin=admin, nav="clients", page_title="کاربران و اشتراک‌ها",
                   clients=rows, nodes=[node], protocols={p: PROTOCOLS[p] for p in SUPPORTED_PROTOCOLS})

@app.post("/clients/create")
async def client_create(request: Request, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db)
    try:
        node = _ensure_railway_node(db, request)
        db.commit()  # Preserve the built-in server record even if a client config fails validation.
        node = db.get(Node, node.id)
        name = _required(data, "name", "نام کاربر", 120)
        protocol = data.get("protocol", "vless").strip().lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise ValueError("در حالت یک‌سرویسی Railway، فقط VLESS، VMess و Trojan از مسیر امن WebSocket پشتیبانی می‌شوند.")
        transport, security, sni = "ws", "tls", node.host
        credential = str(uuid.uuid4()) if protocol in {"vless", "vmess"} else secrets.token_urlsafe(32)
        email = f"rix-{secrets.token_hex(8)}@rix.local"
        tag = f"rix-{secrets.token_hex(12)}"
        port = _next_port(db, node)  # Internal unique ID only; external links use Railway HTTPS port 443.
        quota_bytes = _gib_to_bytes(data.get("quota_gb", "0"), "سهمیه (GB)")
        try:
            days = int(data.get("duration_days", "0") or "0")
        except ValueError as exc:
            raise ValueError("مدت اعتبار باید عدد صحیح باشد.") from exc
        if not 0 <= days <= 3650:
            raise ValueError("مدت اعتبار باید بین صفر تا ۳۶۵۰ روز باشد.")
        expires_at = utcnow() + timedelta(days=days) if days else None
        path = WEBSOCKET_PATHS[protocol]
        config = build_config(node, protocol, transport, security, credential, 443, name, sni,
                              path, "", "", "chacha20-ietf-poly1305")
        inbound_stub = {"runtime": "railway", "protocol": protocol, "path": path}
        sub_token = new_token(32)
        client = Client(name=name, protocol=protocol, transport=transport, security=security, node_id=node.id,
                        port=port, inbound_tag=tag, email=email, credential_encrypted=encrypt_secret(credential),
                        inbound_json_encrypted=encrypt_secret(json.dumps(inbound_stub, separators=(",", ":"))),
                        config_encrypted=encrypt_secret(config), subscription_token_hash=token_hash(sub_token),
                        subscription_token_encrypted=encrypt_secret(sub_token), quota_bytes=quota_bytes,
                        used_bytes=0, expires_at=expires_at, enabled=True,
                        note=data.get("note", "").strip()[:1000] or None)
        db.add(client)
        db.flush()
        _audit(db, admin, "client.create", "client", client.id,
               f"protocol={protocol}; transport=ws; security=tls; public_port=443")
        runtime.sync(db, node.id)
        db.commit()
        _flash(request, "کاربر ساخته شد؛ Xray داخلی به‌روزرسانی شد و لینک روی دامنهٔ Railway ساخته شد.")
    except (ValueError, RuntimeError, ConfigError, HTTPException) as exc:
        db.rollback()
        detail = getattr(exc, "detail", str(exc))
        _flash(request, str(detail), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/toggle")
async def client_toggle(request: Request, client_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db)
    node = _ensure_railway_node(db, request); db.commit()
    client = db.get(Client, client_id)
    if not client:
        _flash(request, "کاربر پیدا نشد.", "error")
        return RedirectResponse("/clients", status_code=303)
    node = db.get(Node, client.node_id)
    try:
        if client.enabled:
            client.enabled = False
            message = "کاربر غیرفعال شد."
        else:
            if client.expires_at and client.expires_at <= utcnow():
                raise ValueError("اعتبار کاربر تمام شده است؛ تاریخ انقضا را اصلاح یا کاربر تازه بساز.")
            if client.quota_bytes and client.used_bytes >= client.quota_bytes:
                raise ValueError("حجم ثبت‌شدهٔ کاربر تمام شده است.")
            if client.protocol not in SUPPORTED_PROTOCOLS:
                raise ValueError("این پروتکل در سرویس یک‌سرویسی Railway پشتیبانی نمی‌شود.")
            client.enabled = True
            message = "کاربر دوباره فعال شد."
        client.updated_at = utcnow()
        _audit(db, admin, "client.toggle", "client", client.id, f"enabled={client.enabled}")
        db.flush()
        runtime.sync(db, node.id)
        db.commit(); _flash(request, message)
    except (RuntimeError, ValueError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/delete")
async def client_delete(request: Request, client_id: int, db: Session = Depends(get_db)):
    await _verify_csrf(request); admin = _admin(request, db)
    _ensure_railway_node(db, request); db.commit()
    client = db.get(Client, client_id)
    if not client:
        _flash(request, "کاربر پیدا نشد.", "error")
        return RedirectResponse("/clients", status_code=303)
    node = db.get(Node, client.node_id)
    try:
        _audit(db, admin, "client.delete", "client", client.id, f"name={client.name}; tag={client.inbound_tag}")
        db.delete(client); db.flush()
        runtime.sync(db, node.id)
        db.commit(); _flash(request, "کاربر از پنل و Xray داخلی حذف شد.")
    except RuntimeError as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.post("/clients/{client_id}/usage")
async def client_usage(request: Request, client_id: int, db: Session = Depends(get_db)):
    data = await _verify_csrf(request); admin = _admin(request, db)
    _ensure_railway_node(db, request); db.commit()
    client = db.get(Client, client_id)
    if not client:
        _flash(request, "کاربر پیدا نشد.", "error")
        return RedirectResponse("/clients", status_code=303)
    try:
        client.used_bytes = _gib_to_bytes(data.get("used_gb", "0"), "مصرف ثبت‌شده (GB)")
        if client.quota_bytes and client.used_bytes > client.quota_bytes:
            raise ValueError("مصرف نمی‌تواند از سهمیه بیشتر باشد.")
        if client.enabled and client.quota_bytes and client.used_bytes >= client.quota_bytes:
            client.enabled = False
        _audit(db, admin, "client.usage.update", "client", client.id,
               f"used_bytes={client.used_bytes}; enabled={client.enabled}")
        db.flush()
        runtime.sync(db, client.node_id)
        db.commit(); _flash(request, "مصرف ثبت‌شده ذخیره شد. توجه: این مقدار هنوز دستی است و آمار زنده نیست.", "info")
    except (ValueError, RuntimeError) as exc:
        db.rollback(); _flash(request, str(exc), "error")
    return RedirectResponse("/clients", status_code=303)

@app.get("/s/{token}", response_class=HTMLResponse)
def public_subscription(request: Request, token: str, db: Session = Depends(get_db)):
    client = db.scalar(select(Client).where(Client.subscription_token_hash == token_hash(token)))
    if not client: raise HTTPException(status_code=404, detail="لینک اشتراک نامعتبر یا باطل شده است.")
    node = db.get(Node, client.node_id)
    if not node: raise HTTPException(status_code=404, detail="سرور این اشتراک دیگر در دسترس نیست.")
    state = _client_state(client, node)
    return _render(request, "subscription.html", hide_shell=True, public=True, client=client, node=node, state=state,
                   page_title="ساب‌پنل اشتراک", token=token, subscription_url=f"{_base_url(request)}/s/{token}",
                   raw_url=f"{_base_url(request)}/sub/{token}.txt", qr_url=f"/s/{token}/qr.png", download_url=f"/s/{token}/download")

def _public_config(token: str, db: Session) -> tuple[Client, Node, str]:
    client = db.scalar(select(Client).where(Client.subscription_token_hash == token_hash(token)))
    if not client: raise HTTPException(status_code=404, detail="لینک اشتراک نامعتبر یا باطل شده است.")
    node = db.get(Node, client.node_id)
    if not node: raise HTTPException(status_code=404, detail="سرور این اشتراک وجود ندارد.")
    status, _ = _client_status(client)
    if not client.enabled or status in {"منقضی‌شده", "حجم تمام‌شده"}:
        raise HTTPException(status_code=410, detail="اشتراک غیرفعال، منقضی یا تمام‌شده است.")
    return client, node, decrypt_secret(client.config_encrypted)

@app.get("/sub/{token}.txt")
def raw_subscription(token: str, db: Session = Depends(get_db)):
    client, _node, config = _public_config(token, db)
    return PlainTextResponse(config + "\n", media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"inline; filename=rix-{client.id}-subscription.txt", "Cache-Control": "no-store"})

@app.get("/s/{token}/download")
def download_subscription(token: str, db: Session = Depends(get_db)):
    client, _node, config = _public_config(token, db)
    suffix = ".conf" if client.protocol == "wireguard" else ".txt"
    return Response(config + ("" if config.endswith("\n") else "\n"), media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="rix-{client.id}-{client.protocol}{suffix}"', "Cache-Control": "no-store"})

@app.get("/s/{token}/qr.png")
def qr_code(token: str, db: Session = Depends(get_db)):
    _client, _node, config = _public_config(token, db)
    import io
    image = qrcode.make(config)
    output = io.BytesIO(); image.save(output, format="PNG")
    return Response(output.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})
