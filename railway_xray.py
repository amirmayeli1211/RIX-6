"""Single-service Xray runtime for Railway HTTP/WebSocket ingress.

The public Railway edge handles HTTPS. Caddy routes three WebSocket paths to
local Xray inbounds; no remote node or external agent is required.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import Client, utcnow
from security import decrypt_secret

SUPPORTED_PROTOCOLS = {"vless": "VLESS", "vmess": "VMess", "trojan": "Trojan"}
WEBSOCKET_PATHS = {
    "vless": "/rws/vless",
    "vmess": "/rws/vmess",
    "trojan": "/rws/trojan",
}
INTERNAL_PORTS = {"vless": 11001, "vmess": 11002, "trojan": 11003}
LOCAL_NODE_MARKER = "local://railway-xray"


class RailwayXray:
    def __init__(self) -> None:
        self.binary = os.getenv("XRAY_BIN", "xray")
        self.config_path = Path(os.getenv("XRAY_CONFIG_PATH", "/tmp/rix-storm-xray/config.json"))
        self.log_path = self.config_path.with_name("xray.log")
        self._process: subprocess.Popen | None = None
        self._lock = threading.RLock()
        self._last_error = ""
        self._last_sync = ""
        self._configured_users = 0
        self._config_hash = ""

    def _binary_path(self) -> str | None:
        if os.path.isabs(self.binary) and Path(self.binary).is_file():
            return self.binary
        return shutil.which(self.binary)

    @staticmethod
    def _usable(client: Client) -> bool:
        if not client.enabled:
            return False
        now = utcnow()
        if client.expires_at and client.expires_at <= now:
            return False
        if client.quota_bytes and client.used_bytes >= client.quota_bytes:
            return False
        return client.protocol in SUPPORTED_PROTOCOLS

    def build_config(self, clients: list[Client], node_id: int | None = None) -> dict[str, Any]:
        by_protocol: dict[str, list[dict[str, Any]]] = {p: [] for p in SUPPORTED_PROTOCOLS}
        count = 0
        for client in clients:
            if node_id is not None and client.node_id != node_id:
                continue
            if not self._usable(client):
                continue
            try:
                credential = decrypt_secret(client.credential_encrypted)
            except Exception as exc:
                raise RuntimeError(
                    f"اعتبارسنجی اطلاعات رمزگذاری‌شدهٔ کاربر «{client.name}» ناموفق بود. "
                    "متغیر DATA_ENCRYPTION_KEY را با مقدار زمان ساخت دیتابیس یکسان نگه دار."
                ) from exc
            if client.protocol == "vless":
                by_protocol["vless"].append({"id": credential, "email": client.email, "level": 0})
            elif client.protocol == "vmess":
                by_protocol["vmess"].append({"id": credential, "alterId": 0, "email": client.email, "level": 0})
            elif client.protocol == "trojan":
                by_protocol["trojan"].append({"password": credential, "email": client.email, "level": 0})
            count += 1

        inbounds: list[dict[str, Any]] = []
        for protocol, port in INTERNAL_PORTS.items():
            if protocol == "vless":
                settings: dict[str, Any] = {"clients": by_protocol[protocol], "decryption": "none"}
            elif protocol == "vmess":
                settings = {"clients": by_protocol[protocol]}
            else:
                settings = {"clients": by_protocol[protocol]}
            inbounds.append({
                "tag": f"rix-{protocol}",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": protocol,
                "settings": settings,
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": WEBSOCKET_PATHS[protocol]},
                },
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            })

        return {
            "log": {"loglevel": os.getenv("XRAY_LOG_LEVEL", "warning")},
            "inbounds": inbounds,
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
            "routing": {"domainStrategy": "AsIs", "rules": []},
        }

    def _stop_locked(self) -> None:
        process = self._process
        self._process = None
        if not process or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def sync(self, db: Session, node_id: int) -> dict[str, Any]:
        """Validate and atomically apply the database's enabled client set."""
        with self._lock:
            binary = self._binary_path()
            if not binary:
                self._last_error = (
                    "هستهٔ Xray در محیط اجرا پیدا نشد. این نسخه باید از Dockerfile همین بسته روی Railway ساخته شود؛ "
                    "از Build Logs بررسی کن که مرحلهٔ نصب Xray کامل شده باشد."
                )
                raise RuntimeError(self._last_error)
            clients = db.scalars(select(Client).where(Client.node_id == node_id).order_by(Client.id)).all()
            config = self.build_config(clients, node_id=node_id)
            serialized = json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            import hashlib
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            usable_count = sum(1 for client in clients if self._usable(client))

            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.config_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            test = subprocess.run(
                [binary, "run", "-test", "-config", str(temporary)],
                capture_output=True, text=True, timeout=20, check=False,
            )
            if test.returncode != 0:
                temporary.unlink(missing_ok=True)
                detail = (test.stderr or test.stdout or "Xray config test failed")[-1600:]
                self._last_error = "Xray تنظیمات داخلی را نپذیرفت: " + detail
                raise RuntimeError(self._last_error)

            temporary.replace(self.config_path)
            if self._process and self._process.poll() is None and self._config_hash == digest:
                self._last_error = ""
                self._last_sync = datetime.utcnow().isoformat(timespec="seconds") + "Z"
                self._configured_users = usable_count
                return self.status()

            self._stop_locked()
            log_handle = self.log_path.open("a", encoding="utf-8")
            try:
                self._process = subprocess.Popen(
                    [binary, "run", "-config", str(self.config_path)],
                    stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            finally:
                log_handle.close()
            time.sleep(0.35)
            if self._process.poll() is not None:
                tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-1600:] if self.log_path.exists() else ""
                self._last_error = "Xray بلافاصله پس از اجرا متوقف شد. " + tail
                self._process = None
                raise RuntimeError(self._last_error)
            self._config_hash = digest
            self._configured_users = usable_count
            self._last_sync = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            self._last_error = ""
            return self.status()

    def start_empty(self) -> None:
        """Start Xray at boot even before the admin opens the dashboard."""
        with self._lock:
            if not self._binary_path():
                self._last_error = "Xray هنوز در این محیط نصب نشده است."
                return
            if self._process and self._process.poll() is None:
                return
            config = self.build_config([])
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            binary = self._binary_path()
            log_handle = self.log_path.open("a", encoding="utf-8")
            try:
                self._process = subprocess.Popen(
                    [binary, "run", "-config", str(self.config_path)],
                    stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            finally:
                log_handle.close()
            time.sleep(0.25)
            if self._process.poll() is not None:
                self._last_error = "Xray راه‌اندازی نشد؛ گزارش در xray.log ثبت شده است."
                self._process = None
                return
            self._config_hash = ""
            self._last_error = ""

    def status(self) -> dict[str, Any]:
        with self._lock:
            installed = bool(self._binary_path())
            running = bool(self._process and self._process.poll() is None)
            return {
                "installed": installed,
                "running": running,
                "state": "online" if running else ("not_installed" if not installed else "offline"),
                "configured_users": self._configured_users,
                "last_sync": self._last_sync or "—",
                "error": self._last_error,
                "pid": self._process.pid if running and self._process else None,
                "protocols": list(SUPPORTED_PROTOCOLS),
            }

    def shutdown(self) -> None:
        with self._lock:
            self._stop_locked()


runtime = RailwayXray()
