from __future__ import annotations
import base64, json, re, uuid
from urllib.parse import urlencode, quote
from models import Node
from security import decrypt_secret

PROTOCOLS = {
    "vless": {"label": "VLESS", "hint": "UUID؛ TLS یا Reality"},
    "vmess": {"label": "VMess", "hint": "UUID؛ TLS یا بدون TLS"},
    "trojan": {"label": "Trojan", "hint": "رمز عبور؛ معمولاً با TLS"},
    "shadowsocks": {"label": "Shadowsocks", "hint": "رمز مستقل برای هر کاربر"},
}
TRANSPORTS = {"tcp", "ws", "grpc", "xhttp"}
SECURITIES = {"none", "tls", "reality"}
SS_CIPHERS = {"chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"}

class ConfigError(ValueError):
    pass

def safe_host(value: str) -> str:
    raw = (value or "").strip().strip("[]")
    if not raw or any(c in raw for c in "/\\@?#%\r\n\t "):
        raise ConfigError("آدرس سرور معتبر نیست.")
    if not re.fullmatch(r"(?i)(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?", raw):
        try:
            import ipaddress
            ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ConfigError("آدرس سرور باید دامنه یا IP معتبر باشد.") from exc
    return raw.rstrip(".").lower()

def _uri_host(value: str) -> str:
    """Return a URI-safe host; IPv6 literals must be wrapped in brackets."""
    host = safe_host(value)
    try:
        import ipaddress
        parsed = ipaddress.ip_address(host)
        return f"[{host}]" if parsed.version == 6 else host
    except ValueError:
        return host


def _transport_settings(data: dict[str, str], sni: str) -> dict:
    network = data["transport"]
    out: dict = {"network": network, "security": data["security"]}
    if network == "ws":
        out["wsSettings"] = {"path": data.get("path") or "/", "headers": {"Host": sni} if sni else {}}
    elif network == "grpc":
        out["grpcSettings"] = {"serviceName": data.get("service_name") or "grpc-service", "multiMode": False}
    elif network == "xhttp":
        out["xhttpSettings"] = {"path": data.get("path") or "/", "mode": "auto"}
    if data["security"] == "tls":
        node = data["_node"]
        if not node.tls_cert_path or not node.tls_key_path:
            raise ConfigError("برای TLS در تنظیمات نود، مسیر گواهی و کلید TLS را وارد کن.")
        out["tlsSettings"] = {
            "serverName": sni,
            "alpn": ["h2", "http/1.1"],
            "certificates": [{"certificateFile": node.tls_cert_path, "keyFile": node.tls_key_path}],
        }
    elif data["security"] == "reality":
        node = data["_node"]
        private_key = decrypt_secret(node.reality_private_key_encrypted)
        if not node.reality_public_key or not node.reality_short_id or not private_key:
            raise ConfigError("برای Reality، کلید خصوصی/عمومی و Short ID را در تنظیمات نود کامل کن.")
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", node.reality_short_id):
            raise ConfigError("Reality Short ID باید ۱ تا ۱۶ رقم هگزادسیمال باشد.")
        if network == "ws":
            raise ConfigError("Reality با WebSocket در این سازنده ترکیب پشتیبانی‌شده‌ای نیست.")
        out["realitySettings"] = {
            "show": False,
            "dest": f"{sni}:443",
            "xver": 0,
            "serverNames": [sni],
            "privateKey": private_key,
            "shortIds": [node.reality_short_id],
        }
    return out

def build_inbound(node: Node, data: dict[str, str], credential: str, email: str, port: int, tag: str) -> dict:
    protocol = data["protocol"]
    network = data["transport"]
    security = data["security"]
    if protocol not in PROTOCOLS: raise ConfigError("پروتکل انتخاب‌شده پشتیبانی نمی‌شود.")
    if network not in TRANSPORTS: raise ConfigError("روش انتقال معتبر نیست.")
    if security not in SECURITIES: raise ConfigError("نوع امنیت معتبر نیست.")
    if network == "xhttp" and protocol != "vless": raise ConfigError("XHTTP در این نسخه فقط با VLESS فعال است.")
    if security == "reality" and protocol != "vless": raise ConfigError("Reality در این نسخه فقط با VLESS فعال است.")
    if protocol == "trojan" and security != "tls": raise ConfigError("برای Trojan از TLS استفاده کن.")
    if protocol == "shadowsocks":
        if network != "tcp" or security != "none": raise ConfigError("Shadowsocks در این نسخه با TCP و بدون TLS ساخته می‌شود.")
        cipher = data.get("cipher", "chacha20-ietf-poly1305")
        if cipher not in SS_CIPHERS: raise ConfigError("Cipher انتخاب‌شده معتبر نیست.")
        settings = {"method": cipher, "password": credential, "network": "tcp,udp"}
        stream = None
    else:
        if security == "tls":
            sni = safe_host(data.get("sni") or node.tls_sni or node.host)
        elif security == "reality":
            sni = safe_host(data.get("sni") or node.reality_sni or "")
        else:
            sni = safe_host(data.get("sni") or node.host)
        stream_data = dict(data)
        stream_data["_node"] = node
        stream = _transport_settings(stream_data, sni)
        if protocol == "vless":
            user = {"id": credential, "email": email}
            flow = data.get("flow", "").strip()
            if flow:
                if security != "reality" or network != "tcp": raise ConfigError("VLESS Flow فقط همراه Reality و TCP انتخاب شود.")
                user["flow"] = flow
            settings = {"clients": [user], "decryption": "none"}
        elif protocol == "vmess":
            if security == "reality": raise ConfigError("VMess با Reality پشتیبانی نمی‌شود.")
            settings = {"clients": [{"id": credential, "alterId": 0, "email": email}]}
        else:  # Trojan
            settings = {"clients": [{"password": credential, "email": email}]}
    inbound = {"tag": tag, "listen": "0.0.0.0", "port": int(port), "protocol": protocol, "settings": settings}
    if stream is not None:
        inbound["streamSettings"] = stream
    inbound["sniffing"] = {"enabled": True, "destOverride": ["http", "tls"]}
    return inbound

def build_config(node: Node, protocol: str, transport: str, security: str, credential: str,
                 port: int, name: str, sni: str = "", path: str = "/", service_name: str = "grpc-service",
                 flow: str = "", cipher: str = "chacha20-ietf-poly1305") -> str:
    host = _uri_host(node.proxy_ip or node.host)
    label = quote(("RIX STORM · " + name)[:70], safe="-_.~")
    params: dict[str, str] = {"type": transport, "security": security}
    if security == "tls":
        params["sni"] = sni or node.tls_sni or node.host
        params["fp"] = "chrome"
    elif security == "reality":
        params.update({"sni": sni or node.reality_sni or node.host,
                       "fp": "chrome", "pbk": node.reality_public_key or "", "sid": node.reality_short_id or ""})
        if flow: params["flow"] = flow
    if transport == "ws": params.update({"host": sni or node.tls_sni or node.host, "path": path or "/"})
    elif transport == "grpc": params["serviceName"] = service_name or "grpc-service"
    elif transport == "xhttp": params.update({"path": path or "/", "mode": "auto"})
    if protocol == "vless":
        params["encryption"] = "none"
        return f"vless://{quote(credential, safe='-._~')}@{host}:{port}?{urlencode(params)}#{label}"
    if protocol == "vmess":
        obj = {"v":"2", "ps":f"RIX STORM · {name}"[:70], "add":host, "port":str(port), "id":credential,
               "aid":"0", "scy":"auto", "net":transport, "type":"none", "host":sni or node.tls_sni or "",
               "path":(service_name if transport == "grpc" else path or "/"),
               "tls":"tls" if security == "tls" else "", "sni":sni or node.tls_sni or "", "fp":"chrome"}
        return "vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()).decode()
    if protocol == "trojan":
        return f"trojan://{quote(credential, safe='-._~')}@{host}:{port}?{urlencode(params)}#{label}"
    if protocol == "shadowsocks":
        raw = f"{cipher}:{credential}".encode()
        method_password = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return f"ss://{method_password}@{host}:{port}#{label}"
    raise ConfigError("پروتکل انتخاب‌شده پشتیبانی نمی‌شود.")

def format_bytes(value: int) -> str:
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB": return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"
