from __future__ import annotations

from typing import Any, Iterable

from packages.shared.workforce_os.auth import (
    AuthContext,
    AuthMiddleware,
    AuthorizationError,
    JWTSigner,
    TENANT_PATH_PATTERN,
    ensure_tenant_access,
    json_response,
)


class SchedulerServiceApp:
    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        if method == "GET" and path == "/health":
            return json_response(start_response, "200 OK", {"status": "ok"})

        match = TENANT_PATH_PATTERN.match(path)
        if method == "GET" and match:
            auth_context = environ.get("workforce.auth")
            if not isinstance(auth_context, AuthContext):
                return json_response(start_response, "401 Unauthorized", {"detail": "Missing bearer token"})

            try:
                ensure_tenant_access(auth_context, match.group("tenant_id"))
            except AuthorizationError as exc:
                return json_response(start_response, "403 Forbidden", {"detail": str(exc)})

            return json_response(
                start_response,
                "200 OK",
                {
                    "jobs": [],
                    "sub": auth_context.subject,
                    "tenant_id": auth_context.tenant_id,
                },
            )

        return json_response(start_response, "404 Not Found", {"detail": "Not found"})


def create_app(signer: JWTSigner | None = None) -> AuthMiddleware:
    return AuthMiddleware(SchedulerServiceApp(), signer or JWTSigner(), public_paths={"/health"})


app = create_app()
