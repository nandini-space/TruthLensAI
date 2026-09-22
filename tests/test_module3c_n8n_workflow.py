"""Static checks for the importable, mock-only Module 3C n8n workflow."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


WORKFLOW_PATH = Path("n8n/workflows/truthlens_module_3c_mock.json")


class Module3CN8nWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = json.loads(WORKFLOW_PATH.read_text(encoding="utf-8"))
        cls.nodes = {node["name"]: node for node in cls.workflow["nodes"]}
        cls.serialized = json.dumps(cls.workflow).lower()

    def test_workflow_has_the_expected_mock_flow_nodes(self) -> None:
        self.assertEqual(
            set(self.nodes),
            {
                "Telegram Trigger",
                "Normalize Telegram Input",
                "Detect Input Type",
                "Mock TruthLensAI Response",
                "Format Telegram Response",
                "Send Telegram Response",
            },
        )

    def test_workflow_is_inactive_and_contains_no_credentials_or_backend_calls(self) -> None:
        self.assertFalse(self.workflow["active"])
        self.assertNotIn("credentials", self.serialized)
        self.assertNotIn("telegram_bot_token", self.serialized)
        self.assertNotIn("/api/module", self.serialized)
        self.assertNotIn("/scan", self.serialized)
        self.assertNotIn("http request", self.serialized)
        self.assertNotIn("fetch(", self.serialized)

    def test_mock_response_uses_the_existing_normalized_envelope(self) -> None:
        mock_code = self.nodes["Mock TruthLensAI Response"]["parameters"]["jsCode"]
        for field in (
            "contract_version",
            "request_id",
            "status",
            "source",
            "scan",
            "threat_intelligence",
            "incident",
            "actions",
            "capabilities",
        ):
            self.assertIn(field, mock_code)
        self.assertIn("Mock detection response", mock_code)
        self.assertNotIn("scan_result", mock_code)

    def test_input_detection_recognizes_all_current_prototype_types(self) -> None:
        normalization_code = self.nodes["Normalize Telegram Input"]["parameters"]["jsCode"]
        detection_code = self.nodes["Detect Input Type"]["parameters"]["jsCode"]
        for input_type in ("text", "image", "audio", "video"):
            self.assertIn(f"'{input_type}'", normalization_code)
        self.assertIn("'url'", detection_code)


if __name__ == "__main__":
    unittest.main()
