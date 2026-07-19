from __future__ import annotations

import re
from typing import Any, Iterable

from packages.shared.workforce_os.auth import APIKeyStore, AuthMiddleware, JWTSigner, json_response, read_json_request

_KEY_ID_PATTERN = re.compile(r"^/v1/auth/keys/([^/]+)$")


class IdentityServiceApp:
    def __init__(self, store: APIKeyStore | None = None, signer: JWTSigner | None = None) -> None:
        self._store = store or APIKeyStore()
        self._signer = signer or JWTSigner()

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        if method == "GET" and path == "/health":
            return json_response(start_response, "200 OK", {"status": "ok"})
        if method == "POST" and path == "/v1/auth/token":
            return self._issue_token(environ, start_response)
        if method == "POST" and path == "/v1/auth/keys":
            return self._create_key(environ, start_response)
        if method == "GET" and path == "/v1/auth/keys":
            return self._list_keys(environ, start_response)
        key_id_match = _KEY_ID_PATTERN.match(path)
        if method == "DELETE" and key_id_match:
            return self._delete_key(environ, start_response, key_id_match.group(1))

        return json_response(start_response, "404 Not Found", {"detail": "Not found"})

    def _create_key(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        auth = environ["workforce.auth"]
        try:
            payload = read_json_request(environ)
            raw_sub = str(payload.get("sub", "")).strip()
            subject = raw_sub if raw_sub else auth.subject
            record, api_key = self._store.create_key(
                tenant_id=auth.tenant_id,
                subject=subject,
                name=str(payload.get("name", "default")),
            )
        except ValueError as exc:
            return json_response(start_response, "400 Bad Request", {"detail": str(exc)})

        return json_response(
            start_response,
            "201 Created",
            {
                "api_key": api_key,
                "created_at": record.created_at,
                "id": record.key_id,
                "name": record.name,
                "sub": record.subject,
                "tenant_id": record.tenant_id,
            },
        )

    def _list_keys(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        auth = environ["workforce.auth"]
        records = self._store.list_keys(auth.tenant_id)
        keys = [
            {
                "created_at": r.created_at,
                "id": r.key_id,
                "last_used": r.last_used_at,
                "name": r.name,
            }
            for r in records
        ]
        return json_response(start_response, "200 OK", {"keys": keys})

    def _delete_key(self, environ: dict[str, Any], start_response: Any, key_id: str) -> Iterable[bytes]:
        auth = environ["workforce.auth"]
        try:
            self._store.revoke_key(key_id, auth.tenant_id)
        except ValueError:
            return json_response(start_response, "404 Not Found", {"detail": "API key not found"})
        return json_response(start_response, "200 OK", {})

    def _issue_token(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        try:
            payload = read_json_request(environ)
        except ValueError as exc:
            return json_response(start_response, "400 Bad Request", {"detail": str(exc)})

        api_key = str(payload.get("api_key", "")).strip()
        if not api_key:
            return json_response(start_response, "400 Bad Request", {"detail": "api_key is required"})

        record = self._store.validate_key(api_key)
        if record is None:
            return json_response(start_response, "401 Unauthorized", {"detail": "Invalid API key"})

        access_token, expires_in = self._signer.issue_token(tenant_id=record.tenant_id, subject=record.subject)
        return json_response(
            start_response,
            "200 OK",
            {
                "access_token": access_token,
                "expires_in": expires_in,
                "token_type": "Bearer",
            },
        )


def create_app(store: APIKeyStore | None = None, signer: JWTSigner | None = None) -> AuthMiddleware:
    effective_signer = signer or JWTSigner()
    return AuthMiddleware(
        IdentityServiceApp(store=store, signer=effective_signer),
        signer=effective_signer,
        public_paths={"/health", "/v1/auth/token"},
    )


app = create_app()
