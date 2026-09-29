import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class WorkflowConfigurationTests(unittest.TestCase):
    def test_workflows_use_node24_action_generations(self):
        for name in ("test.yml", "release.yml"):
            with self.subTest(workflow=name):
                text = (PROJECT_ROOT / ".github" / "workflows" / name).read_text(
                    encoding="utf-8"
                )
                self.assertIn("actions/checkout@v6", text)
                self.assertIn("actions/setup-python@v6", text)
                self.assertNotIn("actions/checkout@v4", text)
                self.assertNotIn("actions/setup-python@v5", text)

    def test_pull_request_workflow_installs_gui_dependencies(self):
        text = (PROJECT_ROOT / ".github" / "workflows" / "test.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pip install -r requirements.txt", text)


if __name__ == "__main__":
    unittest.main()
