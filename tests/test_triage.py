import os
import tempfile
import unittest
from pathlib import Path

import triage


class TriageTests(unittest.TestCase):
    def test_triage_scores_keywords(self):
        result = triage.triage_url("http://secure-paypal-login.com/verify")
        self.assertGreaterEqual(result.score, 20)
        self.assertIn(result.risk, {"medium", "high"})

    def test_load_email_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "emails.csv"
            path.write_text(
                "url,sender,subject\nhttps://example.com,alerts@company.com,Test\n",
                encoding="utf-8",
            )
            rows = triage.load_email_rows(str(path))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sender"], "alerts@company.com")

    def test_ioc_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            results = [triage.triage_url("http://192.168.1.10/update")]
            triage.build_ioc_exports(results, tmp, min_score=0)
            self.assertTrue(Path(tmp, "iocs.txt").exists())
            self.assertTrue(Path(tmp, "iocs.json").exists())
            self.assertTrue(Path(tmp, "stix_bundle.json").exists())


if __name__ == "__main__":
    unittest.main()
