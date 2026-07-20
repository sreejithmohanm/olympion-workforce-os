from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterable

import yaml

from packages.shared.workforce_os.auth import (
    AuthContext,
    AuthMiddleware,
    JWTSigner,
    json_response,
    read_json_request,
)

_CATALOG_ENTRY_PATTERN = re.compile(r"^/v1/catalog/(?P<name>[^/]+)/(?P<version>[^/]+)$")
_EMPLOYEE_ID_PATTERN = re.compile(r"^/v1/employees/(?P<id>[^/]+)$")
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$")

_DPDL_REQUIRED_FIELDS = ("name", "version", "domain", "description", "capabilities")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(now: Callable[[], datetime]) -> str:
    return now().isoformat().replace("+00:00", "Z")


@dataclass
class TemplateRecord:
    name: str
    version: str
    domain: str
    description: str
    capabilities: list[str]
    guardrails: list[Any]
    status: str  # "available" | "invalid"
    error: str | None
    created_at: str
    raw: dict[str, Any]


@dataclass
class EmployeeRecord:
    id: str
    tenant_id: str
    template_name: str
    template_version: str
    display_name: str
    status: str  # "active" | "terminated"
    created_at: str
    terminated_at: str | None = None


class CapabilityRegistry:
    """Registry of known capability names.

    When non-empty, the ingestion pipeline validates that every capability
    referenced in a DPDL template is present in this registry.  An empty
    registry means no capability-name validation is performed (all names are
    accepted), which preserves backward compatibility with deployments that
    have not yet populated the registry.
    """

    def __init__(self, capabilities: Iterable[str] | None = None) -> None:
        self._capabilities: set[str] = {c.strip() for c in capabilities} if capabilities is not None else set()

    def register(self, name: str) -> None:
        """Register a capability name."""
        self._capabilities.add(name.strip())

    def contains(self, name: str) -> bool:
        """Return True if *name* is a registered capability."""
        return name.strip() in self._capabilities

    def is_empty(self) -> bool:
        """Return True when no capabilities have been registered."""
        return not self._capabilities


class TemplateStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], TemplateRecord] = {}

    def register(self, record: TemplateRecord) -> None:
        self._records[(record.name, record.version)] = record

    def get(self, name: str, version: str) -> TemplateRecord | None:
        return self._records.get((name, version))

    def list_available(self) -> list[TemplateRecord]:
        return [r for r in self._records.values() if r.status == "available"]

    def list_all(self) -> list[TemplateRecord]:
        return list(self._records.values())


class EmployeeStore:
    def __init__(self) -> None:
        self._records: dict[str, EmployeeRecord] = {}

    def create(self, record: EmployeeRecord) -> None:
        self._records[record.id] = record

    def get(self, employee_id: str) -> EmployeeRecord | None:
        return self._records.get(employee_id)

    def list_for_tenant(self, tenant_id: str) -> list[EmployeeRecord]:
        return [r for r in self._records.values() if r.tenant_id == tenant_id]

    def terminate(self, employee_id: str, terminated_at: str) -> None:
        record = self._records[employee_id]
        record.status = "terminated"
        record.terminated_at = terminated_at


def _validate_dpdl(raw: dict[str, Any], capability_registry: CapabilityRegistry | None = None) -> tuple[bool, str | None]:
    """Validate a parsed DPDL document. Returns (is_valid, error_message).

    Validation steps:
    1. DPDL schema – required fields, types, and semantic version format.
    2. Capability Registry – every capability name must exist in the registry
       (skipped when the registry is absent or empty).
    3. Guardrail syntax – each guardrail must be a string or a dict.
    """
    for req in _DPDL_REQUIRED_FIELDS:
        if req not in raw or not raw[req]:
            return False, f"Missing required field: {req}"

    if not isinstance(raw["name"], str) or not raw["name"].strip():
        return False, "Field 'name' must be a non-empty string"

    if not isinstance(raw["version"], str) or not _SEMVER_PATTERN.match(raw["version"].strip()):
        return False, "Field 'version' must be a valid semantic version (e.g. 1.0.0)"

    if not isinstance(raw["domain"], str) or not raw["domain"].strip():
        return False, "Field 'domain' must be a non-empty string"

    if not isinstance(raw["description"], str) or not raw["description"].strip():
        return False, "Field 'description' must be a non-empty string"

    caps = raw["capabilities"]
    if not isinstance(caps, list) or len(caps) == 0:
        return False, "Field 'capabilities' must be a non-empty list"
    for cap in caps:
        if not isinstance(cap, str) or not cap.strip():
            return False, "Each capability must be a non-empty string"

    # Step 2: Capability Registry check (skipped when registry is absent or empty)
    if capability_registry is not None and not capability_registry.is_empty():
        for cap in caps:
            cap_name = str(cap).strip()
            if not capability_registry.contains(cap_name):
                return False, f"Unknown capability: '{cap_name}' is not registered in the Capability Registry"

    guardrails = raw.get("guardrails", [])
    if not isinstance(guardrails, list):
        return False, "Field 'guardrails' must be a list"
    for gr in guardrails:
        if not isinstance(gr, (str, dict)):
            return False, "Each guardrail must be a string or an object"

    return True, None


def _read_request_body(environ: dict[str, Any]) -> bytes:
    try:
        content_length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        raise ValueError("Invalid Content-Length")
    return environ["wsgi.input"].read(content_length) if content_length > 0 else b""


def _parse_query_int(query_string: str, param: str, default: int, minimum: int = 0) -> int:
    for part in query_string.split("&"):
        key, _, value = part.partition("=")
        if key == param:
            try:
                parsed = int(value)
                return max(minimum, parsed)
            except ValueError:
                pass
    return default


class EmployeeRegistryApp:
    def __init__(
        self,
        template_store: TemplateStore | None = None,
        employee_store: EmployeeStore | None = None,
        capability_registry: CapabilityRegistry | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._templates = template_store or TemplateStore()
        self._employees = employee_store or EmployeeStore()
        self._capability_registry = capability_registry
        self._now = now or _utc_now

    def __call__(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        if method == "GET" and path == "/health":
            return json_response(start_response, "200 OK", {"status": "ok"})

        if method == "POST" and path == "/v1/catalog/templates":
            return self._register_template(environ, start_response)
        if method == "GET" and path == "/v1/catalog":
            return self._list_catalog(environ, start_response)
        catalog_match = _CATALOG_ENTRY_PATTERN.match(path)
        if method == "GET" and catalog_match:
            return self._get_template(environ, start_response, catalog_match.group("name"), catalog_match.group("version"))

        if method == "POST" and path == "/v1/employees":
            return self._hire_employee(environ, start_response)
        if method == "GET" and path == "/v1/employees":
            return self._list_employees(environ, start_response)
        employee_match = _EMPLOYEE_ID_PATTERN.match(path)
        if method == "GET" and employee_match:
            return self._get_employee(environ, start_response, employee_match.group("id"))
        if method == "DELETE" and employee_match:
            return self._terminate_employee(environ, start_response, employee_match.group("id"))

        return json_response(start_response, "404 Not Found", {"detail": "Not found"})

    # ── Template endpoints ──────────────────────────────────────────────────

    def _register_template(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        raw_body = _read_request_body(environ)
        if not raw_body:
            return json_response(start_response, "400 Bad Request", {"detail": "Request body is required"})

        content_type = environ.get("CONTENT_TYPE", "").lower().split(";")[0].strip()
        try:
            if content_type in ("application/yaml", "text/yaml", "text/x-yaml"):
                try:
                    parsed = yaml.safe_load(raw_body.decode("utf-8"))
                except yaml.YAMLError as exc:
                    return json_response(start_response, "400 Bad Request", {"detail": f"Invalid YAML: {exc}"})
            else:
                try:
                    parsed = json.loads(raw_body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError) as exc:
                    return json_response(start_response, "400 Bad Request", {"detail": "Request body must be valid JSON or YAML"})

            if not isinstance(parsed, dict):
                return json_response(start_response, "400 Bad Request", {"detail": "Template body must be a YAML/JSON object"})
        except UnicodeDecodeError:
            return json_response(start_response, "400 Bad Request", {"detail": "Request body must be UTF-8 encoded"})

        is_valid, error_msg = _validate_dpdl(parsed, self._capability_registry)
        name = str(parsed.get("name", "")).strip()
        version = str(parsed.get("version", "")).strip()
        now_ts = _timestamp(self._now)

        if not is_valid:
            # Store with invalid status if we at least have a name and version
            if name and version:
                record = TemplateRecord(
                    name=name,
                    version=version,
                    domain=str(parsed.get("domain", "")).strip(),
                    description=str(parsed.get("description", "")).strip(),
                    capabilities=parsed.get("capabilities") if isinstance(parsed.get("capabilities"), list) else [],
                    guardrails=parsed.get("guardrails") if isinstance(parsed.get("guardrails"), list) else [],
                    status="invalid",
                    error=error_msg,
                    created_at=now_ts,
                    raw=parsed,
                )
                self._templates.register(record)
            return json_response(
                start_response,
                "422 Unprocessable Entity",
                {"detail": error_msg, "status": "invalid"},
            )

        record = TemplateRecord(
            name=name,
            version=version,
            domain=str(parsed["domain"]).strip(),
            description=str(parsed["description"]).strip(),
            capabilities=[str(c).strip() for c in parsed["capabilities"]],
            guardrails=parsed.get("guardrails", []),
            status="available",
            error=None,
            created_at=now_ts,
            raw=parsed,
        )
        self._templates.register(record)
        return json_response(
            start_response,
            "201 Created",
            _template_summary(record),
        )

    def _list_catalog(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        templates = self._templates.list_available()
        return json_response(
            start_response,
            "200 OK",
            {"templates": [_template_summary(t) for t in templates]},
        )

    def _get_template(self, environ: dict[str, Any], start_response: Any, name: str, version: str) -> Iterable[bytes]:
        record = self._templates.get(name, version)
        if record is None:
            return json_response(start_response, "404 Not Found", {"detail": "Template not found"})
        return json_response(start_response, "200 OK", _template_detail(record))

    # ── Employee endpoints ──────────────────────────────────────────────────

    def _hire_employee(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        auth: AuthContext = environ["workforce.auth"]
        try:
            payload = read_json_request(environ)
        except ValueError as exc:
            return json_response(start_response, "400 Bad Request", {"detail": str(exc)})

        template_name = str(payload.get("template_name", "")).strip()
        template_version = str(payload.get("template_version", "")).strip()
        display_name = str(payload.get("display_name", "")).strip() or template_name

        if not template_name:
            return json_response(start_response, "400 Bad Request", {"detail": "template_name is required"})
        if not template_version:
            return json_response(start_response, "400 Bad Request", {"detail": "template_version is required"})

        template = self._templates.get(template_name, template_version)
        if template is None or template.status != "available":
            reason = "Template not found" if template is None else f"Template status is '{template.status}'"
            return json_response(start_response, "422 Unprocessable Entity", {"detail": reason})

        employee = EmployeeRecord(
            id=uuid.uuid4().hex,
            tenant_id=auth.tenant_id,
            template_name=template_name,
            template_version=template_version,
            display_name=display_name,
            status="active",
            created_at=_timestamp(self._now),
        )
        self._employees.create(employee)
        return json_response(start_response, "201 Created", _employee_detail(employee, template))

    def _list_employees(self, environ: dict[str, Any], start_response: Any) -> Iterable[bytes]:
        auth: AuthContext = environ["workforce.auth"]
        query_string = environ.get("QUERY_STRING", "")
        limit = _parse_query_int(query_string, "limit", default=20, minimum=1)
        offset = _parse_query_int(query_string, "offset", default=0, minimum=0)

        all_employees = self._employees.list_for_tenant(auth.tenant_id)
        page = all_employees[offset : offset + limit]
        return json_response(
            start_response,
            "200 OK",
            {
                "employees": [_employee_summary(e) for e in page],
                "total": len(all_employees),
                "limit": limit,
                "offset": offset,
            },
        )

    def _get_employee(self, environ: dict[str, Any], start_response: Any, employee_id: str) -> Iterable[bytes]:
        auth: AuthContext = environ["workforce.auth"]
        employee = self._employees.get(employee_id)
        if employee is None:
            return json_response(start_response, "404 Not Found", {"detail": "Employee not found"})
        if employee.tenant_id != auth.tenant_id:
            return json_response(start_response, "403 Forbidden", {"detail": "Tenant mismatch"})

        template = self._templates.get(employee.template_name, employee.template_version)
        return json_response(start_response, "200 OK", _employee_detail(employee, template))

    def _terminate_employee(self, environ: dict[str, Any], start_response: Any, employee_id: str) -> Iterable[bytes]:
        auth: AuthContext = environ["workforce.auth"]
        employee = self._employees.get(employee_id)
        if employee is None:
            return json_response(start_response, "404 Not Found", {"detail": "Employee not found"})
        if employee.tenant_id != auth.tenant_id:
            return json_response(start_response, "403 Forbidden", {"detail": "Tenant mismatch"})

        self._employees.terminate(employee_id, _timestamp(self._now))
        employee = self._employees.get(employee_id)
        template = self._templates.get(employee.template_name, employee.template_version)
        return json_response(start_response, "200 OK", _employee_detail(employee, template))


# ── Serialisation helpers ────────────────────────────────────────────────────

def _template_summary(t: TemplateRecord) -> dict[str, Any]:
    return {
        "name": t.name,
        "version": t.version,
        "domain": t.domain,
        "description": t.description,
        "status": t.status,
        "created_at": t.created_at,
    }


def _template_detail(t: TemplateRecord) -> dict[str, Any]:
    result = _template_summary(t)
    result["capabilities"] = t.capabilities
    result["guardrails"] = t.guardrails
    if t.error:
        result["error"] = t.error
    return result


def _employee_summary(e: EmployeeRecord) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": e.id,
        "display_name": e.display_name,
        "status": e.status,
        "template_name": e.template_name,
        "template_version": e.template_version,
        "created_at": e.created_at,
    }
    if e.terminated_at:
        result["terminated_at"] = e.terminated_at
    return result


def _employee_detail(e: EmployeeRecord, template: TemplateRecord | None) -> dict[str, Any]:
    result = _employee_summary(e)
    if template is not None:
        result["template"] = _template_summary(template)
    return result


# ── Application factory ──────────────────────────────────────────────────────

def create_app(
    template_store: TemplateStore | None = None,
    employee_store: EmployeeStore | None = None,
    capability_registry: CapabilityRegistry | None = None,
    signer: JWTSigner | None = None,
    now: Callable[[], datetime] | None = None,
) -> AuthMiddleware:
    return AuthMiddleware(
        EmployeeRegistryApp(
            template_store=template_store,
            employee_store=employee_store,
            capability_registry=capability_registry,
            now=now,
        ),
        signer=signer or JWTSigner(),
        public_paths={"/health"},
    )


app = create_app()
