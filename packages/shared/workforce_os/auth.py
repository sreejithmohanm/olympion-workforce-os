from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(f"{data}{padding}")


@dataclass(slots=True)
class AuthContext:
    tenant_id: str
    subject: str
    issued_at: int
    expires_at: int


@dataclass(slots=True)
class APIKeyRecord:
    key_id: str
    name: str
    tenant_id: str
    subject: str
    key_salt: str
    key_hash: str
    created_at: str
    last_used_at: str | None = None


class AuthenticationError(ValueError):
    """Raised when authentication fails."""


class AuthorizationError(ValueError):
    """Raised when tenant authorization fails."""


class APIKeyStore:
    def __init__(
        self,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._now = now or _utc_now
        self._records_by_id: dict[str, APIKeyRecord] = {}

    def create_key(self, *, tenant_id: str, subject: str, name: str = "default") -> tuple[APIKeyRecord, str]:
        tenant_id = tenant_id.strip()
        subject = subject.strip()
        name = name.strip() or "default"
        if not tenant_id:
            raise ValueError("tenant_id is required")
        if not subject:
            raise ValueError("sub is required")

        key_id = uuid.uuid4().hex
        secret = secrets.token_urlsafe(32)
        salt = os.urandom(16)
        record = APIKeyRecord(
            key_id=key_id,
            name=name,
            tenant_id=tenant_id,
            subject=subject,
            key_salt=_base64url_encode(salt),
            key_hash=self._hash_key(secret, salt),
            created_at=self._timestamp(),
        )
        self._records_by_id[record.key_id] = record
        return record, f"wfos_{record.key_id}.{secret}"

    def list_keys(self, tenant_id: str) -> list[APIKeyRecord]:
        return [r for r in self._records_by_id.values() if r.tenant_id == tenant_id]

    def revoke_key(self, key_id: str, tenant_id: str) -> None:
        record = self._records_by_id.get(key_id)
        if record is None or record.tenant_id != tenant_id:
            raise ValueError("API key not found")
        del self._records_by_id[key_id]

    def validate_key(self, api_key: str) -> APIKeyRecord | None:
        if not api_key:
            return None

        key_id, secret = self._parse_api_key(api_key)
        if not key_id or not secret:
            return None

        record = self._records_by_id.get(key_id)
        if record is None:
            return None

        expected_hash = self._hash_key(secret, _base64url_decode(record.key_salt))
        if not hmac.compare_digest(record.key_hash, expected_hash):
            return None

        record.last_used_at = self._timestamp()
        return record

    def _hash_key(self, secret: str, salt: bytes) -> str:
        return _base64url_encode(hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 600_000))

    def _parse_api_key(self, api_key: str) -> tuple[str | None, str | None]:
        prefix, _, remainder = api_key.partition("_")
        if prefix != "wfos" or not remainder:
            return None, None

        key_id, separator, secret = remainder.partition(".")
        if not separator or not key_id or not secret:
            return None, None

        return key_id, secret

    def _timestamp(self) -> str:
        return self._now().isoformat().replace("+00:00", "Z")


class JWTSigner:
    def __init__(
        self,
        private_key_pem: bytes | None = None,
        ttl_seconds: int | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if private_key_pem is None:
            env_pem = os.environ.get("WORKFORCE_OS_JWT_PRIVATE_KEY_PEM")
            if env_pem:
                private_key_pem = env_pem.encode("utf-8")

        if private_key_pem is not None:
            _pem_passphrase: bytes | None = None
            loaded = serialization.load_pem_private_key(private_key_pem, _pem_passphrase)
            if not isinstance(loaded, RSAPrivateKey):
                raise ValueError("WORKFORCE_OS_JWT_PRIVATE_KEY_PEM must be an RSA private key")
            self._private_key: RSAPrivateKey = loaded
        else:
            self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        self._public_key: RSAPublicKey = self._private_key.public_key()
        self.ttl_seconds = ttl_seconds or int(os.environ.get("WORKFORCE_OS_JWT_TTL_SECONDS", "3600"))
        self._now = now or _utc_now

    def issue_token(self, *, tenant_id: str, subject: str) -> tuple[str, int]:
        now = int(self._now().timestamp())
        claims = {
            "tenant_id": tenant_id,
            "sub": subject,
            "iat": now,
            "exp": now + self.ttl_seconds,
        }
        return self.encode(claims), self.ttl_seconds

    def encode(self, claims: dict[str, Any]) -> str:
        header = {"alg": "RS256", "typ": "JWT"}
        header_segment = _base64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        claims_segment = _base64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
        signature = self._private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header_segment}.{claims_segment}.{_base64url_encode(signature)}"

    def decode(self, token: str) -> AuthContext:
        try:
            header_segment, claims_segment, signature_segment = token.split(".")
        except ValueError as exc:
            raise AuthenticationError("Malformed token") from exc

        signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
        try:
            self._public_key.verify(
                _base64url_decode(signature_segment),
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except (InvalidSignature, ValueError) as exc:
            raise AuthenticationError("Invalid token signature") from exc

        try:
            header = json.loads(_base64url_decode(header_segment))
            claims = json.loads(_base64url_decode(claims_segment))
        except (json.JSONDecodeError, ValueError) as exc:
            raise AuthenticationError("Malformed token payload") from exc

        if header.get("alg") != "RS256" or header.get("typ") != "JWT":
            raise AuthenticationError("Unsupported token header")

        required_claims = ("tenant_id", "sub", "iat", "exp")
        if any(claim not in claims for claim in required_claims):
            raise AuthenticationError("Token is missing required claims")

        try:
            issued_at = int(claims["iat"])
            expires_at = int(claims["exp"])
        except (TypeError, ValueError) as exc:
            raise AuthenticationError("Invalid token timestamps") from exc

        if int(self._now().timestamp()) >= expires_at:
            raise AuthenticationError("Token expired")

        return AuthContext(
            tenant_id=str(claims["tenant_id"]),
            subject=str(claims["sub"]),
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def authenticate_header(self, authorization_header: str | None) -> AuthContext:
        if not authorization_header:
            raise AuthenticationError("Missing bearer token")

        scheme, _, token = authorization_header.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise AuthenticationError("Invalid authorization header")

        return self.decode(token)

    def jwks(self) -> dict[str, Any]:
        pub_numbers = self._public_key.public_numbers()
        n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
        e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
        key_id = hashlib.sha256(n_bytes).hexdigest()
        return {
            "keys": [
                {
                    "alg": "RS256",
                    "e": _base64url_encode(e_bytes),
                    "kid": key_id,
                    "kty": "RSA",
                    "n": _base64url_encode(n_bytes),
                    "use": "sig",
                }
            ]
        }


def ensure_tenant_access(auth_context: AuthContext, tenant_id: str) -> None:
    if auth_context.tenant_id != tenant_id:
        raise AuthorizationError("Tenant mismatch")


def json_response(start_response: Callable[[str, list[tuple[str, str]]], Any], status: str, payload: dict[str, Any]) -> Iterable[bytes]:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def read_json_request(environ: dict[str, Any]) -> dict[str, Any]:
    try:
        content_length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        raise ValueError("Invalid Content-Length")

    raw_body = environ["wsgi.input"].read(content_length) if content_length > 0 else b""
    if not raw_body:
        return {}

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Request body must be valid JSON") from exc

    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")

    return payload


class AuthMiddleware:
    def __init__(self, app: Callable[..., Iterable[bytes]], signer: JWTSigner, public_paths: set[str] | None = None) -> None:
        self._app = app
        self._signer = signer
        self._public_paths = public_paths or {"/health"}

    def __call__(self, environ: dict[str, Any], start_response: Callable[[str, list[tuple[str, str]]], Any]) -> Iterable[bytes]:
        path = environ.get("PATH_INFO", "")
        if path not in self._public_paths:
            try:
                environ["workforce.auth"] = self._signer.authenticate_header(environ.get("HTTP_AUTHORIZATION"))
            except AuthenticationError as exc:
                return json_response(start_response, "401 Unauthorized", {"detail": str(exc)})

        return self._app(environ, start_response)


TENANT_PATH_PATTERN = re.compile(r"^/v1/tenants/(?P<tenant_id>[^/]+)/jobs$")
