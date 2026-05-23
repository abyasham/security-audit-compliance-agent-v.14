import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from eval.ragas_runner import RagasRunner


class TestRagasRunner(unittest.TestCase):
    def test_evaluate_no_findings(self) -> None:
        runner = RagasRunner(llm_gateway=None)
        result = runner.evaluate_sync(findings=[], policy_text="", session_id="s1")
        self.assertEqual(result.get("error"), "no_findings")
        self.assertEqual(result.get("avg_faithfulness"), -1.0)

    def test_faithfulness_capped_without_evidence(self) -> None:
        runner = RagasRunner(llm_gateway=None)
        finding = {
            "id": "f1",
            "ruleName": "Rule A",
            "ruleDescription": "No plaintext protocols",
            "reasoning": "This appears to violate policy based on observed traffic patterns.",
            "confidence": 0.9,
            "evidence": {},
            "evidencePacketNumbers": [],
        }

        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "",
            "OPENROUTER1_API_KEY": "",
            "OPENROUTER2_API_KEY": "",
            "DEEPSEEK_API_KEY": "",
            "KIMI_API_KEY": "",
            "NVIDIA_API_KEY": "",
        }, clear=False):
            result = runner.evaluate_sync(findings=[finding], policy_text="", session_id="s2")

        self.assertEqual(result.get("heuristic_fallback"), True)
        per_scores = result.get("per_finding_scores", [])
        self.assertEqual(len(per_scores), 1)
        self.assertLessEqual(per_scores[0]["faithfulness"], 0.1)

    def test_contexts_include_packet_numbers(self) -> None:
        runner = RagasRunner(llm_gateway=None)
        finding = {
            "evidence": {"details": "Plaintext HTTP request detected."},
            "evidencePacketNumbers": [42, 43],
        }
        contexts = runner._build_contexts(finding, None)
        self.assertIn("Plaintext HTTP request detected.", contexts)
        self.assertIn("Packet 42", contexts)
        self.assertIn("Packet 43", contexts)


if __name__ == "__main__":
    unittest.main()
