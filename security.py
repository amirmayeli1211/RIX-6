from __future__ import annotations
import base64, hashlib, hmac, os, secrets
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


def _fernet() -> Fernet:
    value = os.getenv("DATA_ENCRYPTION_KEY", "").strip()
    if value:
        try:
            return Fernet(value.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("DATA_ENCRYPTION_KEY معتبر نیست؛ یک کلید Fernet بسازید.") from exc
    # Keep the encryption key on the Railway Volume by default; an explicitly
    # configured DATA_ENCRYPTION_KEY always takes precedence for upgrades.
    data_dir = Path(os.getenv("DATA_DIR", "/data" if os.getenv("APP_ENV", "development").lower() == "production" else "."))
    data_dir.mkdir(parents=True, exist_ok=True)
    key_file = data_dir / ".rix-fernet-key"
    if not key_file.exists():
        generated = Fernet.generate_key()
        try:
            fd = os.open(str(key_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(generated)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RuntimeError(f"کلید رمزگذاری در {key_file} ساخته نشد؛ Railway Volume روی /data را بررسی کن.") from exc
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return Fernet(key_file.read_bytes().strip())


def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_secret(value: str | None) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError) as exc:
        raise RuntimeError("رمزگذاری اطلاعات قابل خواندن نیست؛ کلید DATA_ENCRYPTION_KEY را بررسی کنید.") from exc


def new_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, salt_text, digest_text = stored.split("$", 2)
        if kind != "scrypt": return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def csrf_token(session: dict) -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(24)
        session["_csrf"] = token
    return token


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left or "", right or "")
