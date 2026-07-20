from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime

import yaml

from packages.shared.workforce_os.auth import JWTSigner
from services.employee_registry.app import (
    CapabilityRegistry,
    EmployeeStore,
    TemplateStore,
    create_app,
)
from tests.test_identity_service import MutableClock, request_json, serve

_VALID_TEMPLATE = {
    "name": "customer-support-agent",
    "version": "1.0.0",
    "domain": "customer-support",
    "description": "Handles customer inquiries and ticket routing",
    "capabilities": ["ticket-lookup", "escalation-handler"],
    "guardrails": ["no-pii-in-logs"],
}


class EmployeeRegistryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.signer = JWTSigner(ttl_seconds=3600, now=self.clock.now)
        self.templates = TemplateStore()
        self.employees = EmployeeStore()

    def _auth_headers(self, tenant_id: str = "tenant-a") -> dict[str, str]:
        token, _ = self.signer.issue_token(tenant_id=tenant_id, subject="operator")
        return {"Authorization": "Bearer " + token}

    def _app(self):
        return create_app(
            template_store=self.templates,
            employee_store=self.employees,
            signer=self.signer,
            now=self.clock.now,
        )

    # ── Health ───────────────────────────────────────────────────────────────

    def test_health_endpoint_is_public(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(base_url, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "ok")

    # ── Template registration ─────────────────────────────────────────────────

    def test_register_valid_template_json(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 201)
        self.assertEqual(response["name"], "customer-support-agent")
        self.assertEqual(response["version"], "1.0.0")
        self.assertEqual(response["status"], "available")

    def test_register_valid_template_yaml(self) -> None:
        yaml_body = yaml.dump(_VALID_TEMPLATE).encode("utf-8")
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="operator")
        with serve(self._app()) as base_url:
            request = urllib.request.Request(
                f"{base_url}/v1/catalog/templates",
                data=yaml_body,
                method="POST",
                headers={
                    "Content-Type": "application/yaml",
                    "Authorization": "Bearer " + token,
                    "Content-Length": str(len(yaml_body)),
                },
            )
            with urllib.request.urlopen(request) as resp:
                status, response = resp.status, json.loads(resp.read())
        self.assertEqual(status, 201)
        self.assertEqual(response["status"], "available")

    def test_register_template_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
            )
        self.assertEqual(status, 401)

    def test_register_invalid_template_returns_422(self) -> None:
        bad_template = {**_VALID_TEMPLATE, "capabilities": []}
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", bad_template,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertEqual(response["status"], "invalid")
        self.assertIn("capabilities", response["detail"])

    def test_register_template_missing_required_field_returns_422(self) -> None:
        incomplete = {k: v for k, v in _VALID_TEMPLATE.items() if k != "domain"}
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", incomplete,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertIn("domain", response["detail"])

    def test_register_template_invalid_version_returns_422(self) -> None:
        bad = {**_VALID_TEMPLATE, "version": "v1"}
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", bad,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)

    def test_register_template_empty_body_returns_400(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="operator")
        with serve(self._app()) as base_url:
            request = urllib.request.Request(
                f"{base_url}/v1/catalog/templates",
                data=b"",
                method="POST",
                headers={"Authorization": "Bearer " + token},
            )
            try:
                with urllib.request.urlopen(request) as resp:
                    status, response = resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                status, response = exc.code, json.loads(exc.read())
        self.assertEqual(status, 400)

    # ── Capability Registry validation ────────────────────────────────────────

    def _app_with_capabilities(self, *capability_names: str):
        registry = CapabilityRegistry(capability_names)
        return create_app(
            template_store=self.templates,
            employee_store=self.employees,
            capability_registry=registry,
            signer=self.signer,
            now=self.clock.now,
        )

    def test_capability_registry_is_empty_by_default(self) -> None:
        registry = CapabilityRegistry()
        self.assertTrue(registry.is_empty())

    def test_capability_registry_register_and_contains(self) -> None:
        registry = CapabilityRegistry()
        registry.register("ticket-lookup")
        self.assertTrue(registry.contains("ticket-lookup"))
        self.assertFalse(registry.contains("unknown-cap"))

    def test_capability_registry_init_with_capabilities(self) -> None:
        registry = CapabilityRegistry(["ticket-lookup", "escalation-handler"])
        self.assertFalse(registry.is_empty())
        self.assertTrue(registry.contains("ticket-lookup"))
        self.assertTrue(registry.contains("escalation-handler"))
        self.assertFalse(registry.contains("other-cap"))

    def test_register_template_unknown_capability_returns_422(self) -> None:
        """Capability Registry check rejects templates with unregistered capability names."""
        with serve(self._app_with_capabilities("ticket-lookup", "escalation-handler")) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates",
                {**_VALID_TEMPLATE, "capabilities": ["unknown-capability"]},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertEqual(response["status"], "invalid")
        self.assertIn("unknown-capability", response["detail"])

    def test_register_template_known_capabilities_returns_201(self) -> None:
        """Capability Registry check passes when all capability names are registered."""
        with serve(self._app_with_capabilities("ticket-lookup", "escalation-handler")) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 201)
        self.assertEqual(response["status"], "available")

    def test_register_template_empty_capability_registry_skips_check(self) -> None:
        """When no capabilities are registered, the registry check is skipped."""
        with serve(self._app_with_capabilities()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 201)
        self.assertEqual(response["status"], "available")

    def test_register_template_partial_unknown_capability_returns_422(self) -> None:
        """Only one unknown capability is sufficient to fail the registry check."""
        with serve(self._app_with_capabilities("ticket-lookup")) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertIn("escalation-handler", response["detail"])

    # ── Catalog listing ───────────────────────────────────────────────────────


    def test_list_catalog_returns_available_templates(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "GET", "/v1/catalog",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertIn("templates", response)
        self.assertEqual(len(response["templates"]), 1)
        self.assertEqual(response["templates"][0]["name"], "customer-support-agent")

    def test_list_catalog_excludes_invalid_templates(self) -> None:
        bad_template = {**_VALID_TEMPLATE, "name": "bad-agent", "capabilities": []}
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            request_json(
                base_url, "POST", "/v1/catalog/templates", bad_template,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "GET", "/v1/catalog",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(len(response["templates"]), 1)
        self.assertEqual(response["templates"][0]["name"], "customer-support-agent")

    def test_list_catalog_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(base_url, "GET", "/v1/catalog")
        self.assertEqual(status, 401)

    # ── Get template by name+version ──────────────────────────────────────────

    def test_get_template_returns_full_detail(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "GET", "/v1/catalog/customer-support-agent/1.0.0",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["name"], "customer-support-agent")
        self.assertEqual(response["version"], "1.0.0")
        self.assertIn("capabilities", response)
        self.assertIn("guardrails", response)

    def test_get_nonexistent_template_returns_404(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "GET", "/v1/catalog/unknown/9.9.9",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 404)

    def test_get_template_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(base_url, "GET", "/v1/catalog/customer-support-agent/1.0.0")
        self.assertEqual(status, 401)

    # ── Employee hire ────────────────────────────────────────────────────────

    def test_hire_employee_returns_201_with_resource(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url,
                "POST",
                "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0", "display_name": "Alice"},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 201)
        self.assertIn("id", response)
        self.assertEqual(response["status"], "active")
        self.assertEqual(response["display_name"], "Alice")
        self.assertIn("template", response)
        self.assertIn("created_at", response)
        self.assertEqual(str(uuid.UUID(response["id"])), response["id"])

    def test_hire_employee_assigns_stable_uuid(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            _, emp = request_json(
                base_url,
                "POST",
                "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
            emp_id = emp["id"]
            _, fetched = request_json(
                base_url, "GET", f"/v1/employees/{emp_id}",
                headers=self._auth_headers(),
            )
        self.assertEqual(fetched["id"], emp_id)

    def test_hire_employee_default_display_name(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url,
                "POST",
                "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 201)
        self.assertEqual(response["display_name"], "customer-support-agent")

    def test_hire_two_employees_same_template(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            _, emp1 = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
            _, emp2 = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
        self.assertNotEqual(emp1["id"], emp2["id"])

    def test_hire_from_nonexistent_template_returns_422(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "ghost-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertIn("Template not found", response["detail"])

    def test_hire_from_invalid_template_returns_422(self) -> None:
        bad_template = {**_VALID_TEMPLATE, "name": "bad-agent", "capabilities": []}
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", bad_template,
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "bad-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 422)
        self.assertIn("invalid", response["detail"])

    def test_hire_employee_missing_template_name_returns_400(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "POST", "/v1/employees",
                {"template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 400)
        self.assertIn("template_name", response["detail"])

    def test_hire_employee_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
            )
        self.assertEqual(status, 401)

    # ── Employee list ────────────────────────────────────────────────────────

    def test_list_employees_returns_tenant_employees(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers("tenant-a"),
            )
            request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers("tenant-a"),
            )
            request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers("tenant-b"),
            )
            status, response = request_json(
                base_url, "GET", "/v1/employees",
                headers=self._auth_headers("tenant-a"),
            )
        self.assertEqual(status, 200)
        self.assertEqual(len(response["employees"]), 1)
        self.assertIn("total", response)

    def test_list_employees_pagination(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            for i in range(5):
                request_json(
                    base_url, "POST", "/v1/employees",
                    {"template_name": "customer-support-agent", "template_version": "1.0.0", "display_name": f"emp-{i}"},
                    headers=self._auth_headers(),
                )
            status, response = request_json(
                base_url, "GET", "/v1/employees?limit=2&offset=0",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(len(response["employees"]), 2)
        self.assertEqual(response["total"], 5)

    def test_list_employees_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(base_url, "GET", "/v1/employees")
        self.assertEqual(status, 401)

    # ── Employee get ─────────────────────────────────────────────────────────

    def test_get_employee_returns_full_detail(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            _, emp = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0", "display_name": "Bob"},
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "GET", f"/v1/employees/{emp['id']}",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["id"], emp["id"])
        self.assertEqual(response["display_name"], "Bob")
        self.assertIn("template", response)

    def test_get_nonexistent_employee_returns_404(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "GET", "/v1/employees/doesnotexist",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 404)

    def test_get_other_tenant_employee_returns_403(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers("tenant-a"),
            )
            _, emp = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers("tenant-a"),
            )
            status, response = request_json(
                base_url, "GET", f"/v1/employees/{emp['id']}",
                headers=self._auth_headers("tenant-b"),
            )
        self.assertEqual(status, 403)

    def test_get_employee_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(base_url, "GET", "/v1/employees/someid")
        self.assertEqual(status, 401)

    # ── Employee terminate ────────────────────────────────────────────────────

    def test_terminate_employee_sets_status_terminated(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            _, emp = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "DELETE", f"/v1/employees/{emp['id']}",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "terminated")
        self.assertIn("terminated_at", response)

    def test_terminated_employee_is_retained_not_deleted(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers(),
            )
            _, emp = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers(),
            )
            emp_id = emp["id"]
            request_json(
                base_url, "DELETE", f"/v1/employees/{emp_id}",
                headers=self._auth_headers(),
            )
            status, response = request_json(
                base_url, "GET", f"/v1/employees/{emp_id}",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "terminated")

    def test_terminate_nonexistent_employee_returns_404(self) -> None:
        with serve(self._app()) as base_url:
            status, response = request_json(
                base_url, "DELETE", "/v1/employees/ghost",
                headers=self._auth_headers(),
            )
        self.assertEqual(status, 404)

    def test_terminate_other_tenant_employee_returns_403(self) -> None:
        with serve(self._app()) as base_url:
            request_json(
                base_url, "POST", "/v1/catalog/templates", _VALID_TEMPLATE,
                headers=self._auth_headers("tenant-a"),
            )
            _, emp = request_json(
                base_url, "POST", "/v1/employees",
                {"template_name": "customer-support-agent", "template_version": "1.0.0"},
                headers=self._auth_headers("tenant-a"),
            )
            status, response = request_json(
                base_url, "DELETE", f"/v1/employees/{emp['id']}",
                headers=self._auth_headers("tenant-b"),
            )
        self.assertEqual(status, 403)

    def test_terminate_employee_requires_auth(self) -> None:
        with serve(self._app()) as base_url:
            status, _ = request_json(base_url, "DELETE", "/v1/employees/someid")
        self.assertEqual(status, 401)
