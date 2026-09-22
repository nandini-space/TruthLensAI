"""Static contract checks for the Module 3C n8n scan/action workflow."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


class Module3CN8nWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        workflow = json.loads(Path("n8n/workflows/truthlens_module_3c_mock.json").read_text())
        cls.workflow = workflow
        cls.nodes = {node["name"]: node for node in workflow["nodes"]}
        cls.serialized = json.dumps(workflow).lower()

    def test_successful_scan_has_all_result_buttons(self) -> None:
        node = self.nodes["Send Scan Result With Buttons"]
        markup = node["parameters"]["inlineKeyboard"]["rows"]
        data = json.dumps(markup)
        for action in ("WHY_SUSPICIOUS:", "WHAT_TO_DO:", "FULL_REPORT:"):
            self.assertIn(action, data)
        self.assertIn("request_id", data)

    def test_actions_use_persisted_context_and_safe_fallbacks(self) -> None:
        code = self.nodes["Handle Result Action"]["parameters"]["jsCode"]
        self.assertIn("getWorkflowStaticData('global')", code)
        self.assertIn("scan_contexts", code)
        self.assertIn("Why suspicious?", code)
        self.assertIn("What should I do?", code)
        self.assertIn("Full report is not available", code)
        self.assertIn("no longer available", code)
        self.assertIn("No detector signals", code)
        self.assertIn("No specific recommendation", code)

    def test_callback_is_acknowledged_and_never_calls_a_backend(self) -> None:
        ack = self.nodes["Acknowledge Result Action"]["parameters"]
        self.assertEqual((ack["resource"], ack["operation"]), ("callback", "answerQuery"))
        action_connections = self.workflow["connections"]["Handle Result Action"]["main"][0]
        self.assertIn("Acknowledge Result Action", {item["node"] for item in action_connections})
        self.assertNotIn("http", self.nodes["Handle Result Action"]["parameters"]["jsCode"].lower())

    def test_module1_contract_and_mock_mode_remain_available(self) -> None:
        prepare = self.nodes["Prepare Module 1 Request"]["parameters"]["jsCode"]
        request = self.nodes["Call Module 1 Scan API"]["parameters"]
        self.assertIn("TRUTHLENSAI_MOCK_MODE", prepare)
        self.assertIn("'/scan/url'", prepare)
        self.assertIn("'/scan/text'", prepare)
        self.assertIn("{url:e.content}", prepare)
        self.assertIn("{text:e.content}", prepare)
        self.assertIn("TRUTHLENSAI_BACKEND_URL", prepare)
        self.assertIn("$json.backend_url + $json.module1.path", request["url"])

    def test_no_module2_or_secret_is_exported(self) -> None:
        self.assertFalse(self.workflow["active"])
        self.assertNotIn("module2", self.serialized)
        self.assertNotIn("telegram_bot_token", self.serialized)
        self.assertFalse(any("credentials" in node for node in self.nodes.values()))


if __name__ == "__main__":
    unittest.main()
