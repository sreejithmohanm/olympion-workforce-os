from __future__ import annotations

from typing import Any, Iterable

from packages.shared.workforce_os.auth import APIKeyStore, JWTSigner, json_response, read_json_request


class IdentityServiceApp:
    def __init__(self, store: APIKeyStore | None = None, signer: JWTSigner | None = None) -> None:
        self._store = store or APIKeyStore()
        self._signer = signer or JWTSigner()

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        if method == "GET" and path == "/health":
            return json_response(start_response, "200 OK", {"status": "ok"})
        if method == "POST" and path == "/v1/auth/keys":
            return self._create_key(environ, start_response)
        if method == "POST" and path == "/v1/auth/token":
            return self._issue_token(environ, start_response)

        return json_response(start_response, "404 Not Found", {"detail": "Not found"})

    def _create_key(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        try:
            payload = read_json_request(environ)
            record, api_key = self._store.create_key(
                tenant_id=str(payload.get("tenant_id", "")).strip(),
                subject=str(payload.get("sub", "")).strip(),
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


def create_app(store: APIKeyStore | None = None, signer: JWTSigner | None = None) -> IdentityServiceApp:
    return IdentityServiceApp(store=store, signer=signer)


app = create_app()
