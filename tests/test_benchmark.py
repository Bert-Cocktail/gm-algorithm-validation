"""Tests for the cryptographic performance report tool."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import benchmark


class TestBenchmark(unittest.TestCase):
    def test_quick_gmssl_report_contains_all_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            json_path = directory / "benchmark.json"
            markdown_path = directory / "benchmark.md"
            exit_code = benchmark.main([
                "--backend", "gmssl", "--quick",
                "--json", str(json_path), "--markdown", str(markdown_path),
            ])
            report = json.loads(json_path.read_text(encoding="utf-8"))
            operations = {item["operation"] for item in report["measurements"]}
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                operations,
                {"SM3", "HMAC-SM3", "SM4-CTR-encrypt", "SM2-encrypt", "SM2-decrypt"},
            )
            self.assertTrue(all(item["status"] == "measured" for item in report["measurements"]))
            self.assertIn("Cryptographic Performance Report", markdown_path.read_text(encoding="utf-8"))

    def test_invalid_sizes_are_rejected(self) -> None:
        self.assertEqual(benchmark.main(["--backend", "gmssl", "--sizes", "0"]), 2)


if __name__ == "__main__":
    unittest.main()
