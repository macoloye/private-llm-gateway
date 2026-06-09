from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from typing import Any

from gateway.config import APIKey, AuthConfig, ConfigError, JWTConfig


@dataclass(frozen=True)
class Principal:
    id: str
    tenant: str
    allowed_models: tuple[str, ...] = ()
    auth_type: str = "api_key"


class APIKeyStore:
    def __init__(self, config: AuthConfig) -> None:
        self._static_keys = config.api_keys
        self._path = Path(config.api_key_file) if config.api_key_file else None
        self._mtime_ns: int | None = None
        self._dynamic_keys: tuple[APIKey, ...] = ()
        self._load_error = False
        self._load_dynamic_keys(force=True)

    def authenticate(self, supplied: str) -> Principal | None:
        self._load_dynamic_keys()
        if self._load_error:
            return None
        for api_key in (*self._static_keys, *self._dynamic_keys):
            if api_key.revoked:
                continue
            if _matches_key(api_key, supplied):
                return Principal(api_key.id, api_key.tenant, api_key.allowed_models, "api_key")
        return None

    def _load_dynamic_keys(self, *, force: bool = False) -> None:
        if not self._path:
            return
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            self._dynamic_keys = ()
            self._mtime_ns = None
            return
        if not force and stat.st_mtime_ns == self._mtime_ns:
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            records = raw.get("api_keys", raw if isinstance(raw, list) else [])
            keys = tuple(_parse_key_record(item) for item in records)
        except (ConfigError, OSError, json.JSONDecodeError, TypeError, AttributeError):
            self._dynamic_keys = ()
            self._load_error = True
            self._mtime_ns = stat.st_mtime_ns
            return
        self._dynamic_keys = keys
        self._load_error = False
        self._mtime_ns = stat.st_mtime_ns


def issue_api_key(
    path: str | os.PathLike[str],
    *,
    key_id: str,
    tenant: str,
    allowed_models: tuple[str, ...] = (),
) -> str:
    plaintext = f"pig_{secrets.token_urlsafe(32)}"
    record = {
        "id": key_id,
        "tenant": tenant,
        "key_hash": hash_api_key(plaintext),
        "allowed_models": list(allowed_models),
        "revoked": False,
        "created_at": int(time.time()),
    }
    records = _read_records(path)
    if any(item.get("id") == key_id for item in records):
        raise ConfigError(f"api key already exists: {key_id}")
    records.append(record)
    _write_records(path, records)
    return plaintext


def update_api_key(
    path: str | os.PathLike[str],
    *,
    key_id: str,
    tenant: str | None = None,
    allowed_models: tuple[str, ...] | None = None,
    revoked: bool | None = None,
) -> None:
    records = _read_records(path)
    for item in records:
        if item.get("id") == key_id:
            if tenant is not None:
                item["tenant"] = tenant
            if allowed_models is not None:
                item["allowed_models"] = list(allowed_models)
            if revoked is not None:
                item["revoked"] = revoked
            _write_records(path, records)
            return
    raise ConfigError(f"api key not found: {key_id}")


def rotate_api_key(path: str | os.PathLike[str], *, key_id: str) -> str:
    plaintext = f"pig_{secrets.token_urlsafe(32)}"
    records = _read_records(path)
    for item in records:
        if item.get("id") == key_id:
            item["key_hash"] = hash_api_key(plaintext)
            item["rotated_at"] = int(time.time())
            item["revoked"] = False
            _write_records(path, records)
            return plaintext
    raise ConfigError(f"api key not found: {key_id}")


def hash_api_key(plaintext: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, 210_000)
    return "pbkdf2_sha256$210000$" + _b64url(salt) + "$" + _b64url(digest)


class JWTVerifier:
    def __init__(self, config: JWTConfig) -> None:
        self.config = config
        self._mtime_ns: int | None = None
        self._keys: dict[str, bytes] = {}
        self._load_keys(force=True)

    def verify(self, token: str) -> Principal | None:
        if not self.config.enabled:
            return None
        self._load_keys()
        try:
            header, payload, signature = token.split(".", 2)
            header_json = json.loads(_b64decode(header))
            claims = json.loads(_b64decode(payload))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if header_json.get("alg") != "HS256":
            return None
        key_id = header_json.get("kid")
        if not isinstance(key_id, str) or key_id not in self._keys:
            return None
        signing_input = f"{header}.{payload}".encode("ascii")
        expected = hmac.new(self._keys[key_id], signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64decode(signature), expected):
            return None
        now = int(time.time())
        if claims.get("iss") != self.config.issuer:
            return None
        if not _audience_matches(claims.get("aud"), self.config.audience):
            return None
        if int(claims.get("exp", 0)) <= now:
            return None
        tenant = claims.get(self.config.tenant_claim) or claims.get("sub")
        if not isinstance(tenant, str) or not tenant:
            return None
        models = claims.get(self.config.allowed_models_claim, [])
        if not isinstance(models, list):
            models = []
        return Principal(str(claims.get("sub", tenant)), tenant, tuple(str(item) for item in models), "jwt")

    def _load_keys(self, *, force: bool = False) -> None:
        if not self.config.jwks_file:
            return
        path = Path(self.config.jwks_file)
        stat = path.stat()
        if not force and stat.st_mtime_ns == self._mtime_ns:
            return
        raw = json.loads(path.read_text(encoding="utf-8"))
        keys: dict[str, bytes] = {}
        for item in raw.get("keys", []):
            if item.get("kty") == "oct" and item.get("kid") and item.get("k"):
                keys[str(item["kid"])] = _b64decode(str(item["k"]))
        if not keys:
            raise ConfigError("auth.jwt.jwks_file must contain at least one oct key")
        self._keys = keys
        self._mtime_ns = stat.st_mtime_ns


def _matches_key(api_key: APIKey, supplied: str) -> bool:
    if api_key.secret and secrets.compare_digest(supplied, api_key.secret):
        return True
    if not api_key.secret_hash:
        return False
    try:
        algorithm, rounds, salt, digest = api_key.secret_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    expected = hashlib.pbkdf2_hmac("sha256", supplied.encode("utf-8"), _b64decode(salt), int(rounds))
    return hmac.compare_digest(_b64decode(digest), expected)


def _parse_key_record(raw: dict[str, Any]) -> APIKey:
    key_id = str(raw.get("id", "")).strip()
    tenant = str(raw.get("tenant", key_id)).strip()
    key_hash = str(raw.get("key_hash", "")).strip()
    if not key_id or not tenant or not key_hash:
        raise ConfigError("dynamic API key records require id, tenant, and key_hash")
    return APIKey(
        id=key_id,
        tenant=tenant,
        secret="",
        secret_hash=key_hash,
        allowed_models=tuple(str(item) for item in raw.get("allowed_models", [])),
        revoked=bool(raw.get("revoked", False)),
    )


def _read_records(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    target = Path(path)
    if not target.exists():
        return []
    raw = json.loads(target.read_text(encoding="utf-8"))
    records = raw.get("api_keys", raw if isinstance(raw, list) else [])
    if not isinstance(records, list):
        raise ConfigError("api key file must contain an api_keys list")
    return [dict(item) for item in records]


def _write_records(path: str | os.PathLike[str], records: list[dict[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({"api_keys": records}, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _audience_matches(actual: Any, expected: str | None) -> bool:
    if expected is None:
        return False
    if isinstance(actual, str):
        return actual == expected
    if isinstance(actual, list):
        return expected in actual
    return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))
