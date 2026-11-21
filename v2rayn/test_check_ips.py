import subprocess
import unittest
from unittest.mock import patch, Mock

from check_ips import check

class CandidateVerificationTests(unittest.TestCase):
    @patch("check_ips.subprocess.run")
    def test_valid_https_uses_sni_preserving_resolve(self, run):
        run.return_value = Mock(stdout="200 0.125 0.235")
        result = check("example.com", "104.17.99.242", 10)
        self.assertTrue(result["verified"])
        self.assertEqual(result["latency_ms"], 235)
        argv = run.call_args.args[0]
        self.assertIn("--resolve", argv)
        self.assertIn("example.com:443:104.17.99.242", argv)
        self.assertIn("https://example.com/", argv)
        self.assertNotIn("--insecure", argv)

    @patch("check_ips.subprocess.run")
    def test_http_5xx_rejected(self, run):
        run.return_value = Mock(stdout="503 0.125 0.235")
        self.assertIsNone(check("example.com", "104.17.99.242", 10))

    @patch("check_ips.subprocess.run")
    def test_transport_error_rejected(self, run):
        run.side_effect = subprocess.CalledProcessError(60, ["curl"])
        self.assertIsNone(check("example.com", "104.17.99.242", 10))

if __name__ == "__main__":
    unittest.main()
