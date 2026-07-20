from __future__ import annotations

import unittest
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_SPEC_PATH = _ROOT / "api" / "openapi" / "v1" / "openapi.yaml"
_DOCS_PATH = _ROOT / "docs" / "api" / "v1.html"
_TYPES_PATH = _ROOT / "sdk" / "typescript" / "src" / "types" / "v1.ts"


class OpenAPIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(_SPEC_PATH.read_text(encoding="utf-8"))

    def test_spec_is_openapi_31(self) -> None:
        self.assertEqual(self.spec["openapi"], "3.1.0")

    def test_phase1_paths_are_present(self) -> None:
        expected_paths = {
            "/v1/auth/token": {"post"},
            "/v1/auth/keys": {"post", "get"},
            "/v1/auth/keys/{id}": {"delete"},
            "/v1/catalog": {"get"},
            "/v1/catalog/{name}/{version}": {"get"},
            "/v1/catalog/install": {"post"},
            "/v1/employees": {"post", "get"},
            "/v1/employees/{id}": {"get", "delete"},
            "/v1/employees/{id}/work": {"post"},
            "/v1/employees/{id}/work/{workId}": {"get"},
        }

        for path_name, methods in expected_paths.items():
            self.assertIn(path_name, self.spec["paths"])
            self.assertTrue(methods.issubset(set(self.spec["paths"][path_name].keys())))

    def test_reusable_core_schemas_exist(self) -> None:
        schemas = self.spec["components"]["schemas"]
        for schema_name in ("Employee", "ApiKey", "Error", "TemplateDetail", "WorkItem"):
            self.assertIn(schema_name, schemas)

    def test_work_endpoint_documents_sse(self) -> None:
        response = self.spec["paths"]["/v1/employees/{id}/work/{workId}"]["get"]["responses"]["200"]
        self.assertIn("text/event-stream", response["content"])
        example = response["content"]["text/event-stream"]["examples"]["queued"]["value"]
        self.assertIn("event: work.accepted", example)
        self.assertIn("event: work.completed", example)

    def test_generated_artifacts_exist(self) -> None:
        self.assertTrue(_DOCS_PATH.is_file())
        self.assertTrue(_TYPES_PATH.is_file())

    def test_generated_types_include_work_path(self) -> None:
        generated = _TYPES_PATH.read_text(encoding="utf-8")
        self.assertIn('"/v1/employees/{id}/work/{workId}"', generated)

    def test_generated_docs_include_contract_title(self) -> None:
        html = _DOCS_PATH.read_text(encoding="utf-8")
        self.assertIn("<title>Olympion Workforce OS Phase 1 API</title>", html)
