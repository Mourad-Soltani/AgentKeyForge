# AgentKeyForge health tests
# Built by Mourad.Soltani
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Ensure we can import the module
sys.path.insert(0, str(Path(__file__).parent))
from agentkeyforge import generate_key, score_key, shannon_entropy, scan_path, VERSION, SIGNATURE


class TestAgentKeyForge(unittest.TestCase):
    def test_generate_length_and_entropy(self):
        key, bits = generate_key(length=24, charset="alphanum")
        self.assertEqual(len(key), 24)
        self.assertGreater(bits, 80)

    def test_generate_with_prefix(self):
        key, bits = generate_key(length=16, charset="hex", prefix="sk-")
        self.assertTrue(key.startswith("sk-"))
        self.assertEqual(len(key), 19)
        self.assertGreater(bits, 40)

    def test_score_key(self):
        result = score_key("aaaaaaaaaaaaaaaa")
        self.assertEqual(result["rating"], "weak")
        self.assertEqual(result["signature"], SIGNATURE)
        strong = score_key("aB3!xY9#kL2$mN8&pQ4*")
        self.assertGreater(strong["entropy_bits"], 50)

    def test_shannon_entropy_basic(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertLess(shannon_entropy("aaaa"), 1.0)
        self.assertGreater(shannon_entropy("abcd"), shannon_entropy("aaaa"))

    def test_scan_detects_pattern(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            secret_file = Path(td) / "config.md"
            secret_file.write_text("api_key = sk-abc123def456ghi789jkl012\nnormal text\n")
            findings = scan_path(secret_file)
            self.assertGreaterEqual(len(findings), 1)
            kinds = [f["kind"] for f in findings]
            self.assertTrue(any("openai_or_stripe_key" in k or "generic_secret" in k for k in kinds))

    def test_cli_generate_json(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "agentkeyforge.py"), "generate", "--length", "20", "--json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        self.assertIn("key", data)
        self.assertEqual(data["length"], 20)
        self.assertEqual(data["signature"], SIGNATURE)
        self.assertEqual(data["version"], VERSION)

    def test_cli_score(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).parent / "agentkeyforge.py"), "score", "testkey123"],
            capture_output=True, text=True, check=True
        )
        self.assertIn("Entropy:", result.stdout)
        self.assertIn(SIGNATURE, result.stdout)


if __name__ == "__main__":
    unittest.main()
