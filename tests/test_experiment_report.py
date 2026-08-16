"""Tests for archival Markdown experiment reports."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import acvp_adapter
import experiment_report


class TestExperimentReport(unittest.TestCase):
    def write_inputs(self, directory: Path) -> tuple[Path, Path, Path]:
        vector = directory / "vector.json"
        acvp = directory / "acvp.json"
        manifest = directory / "manifest.json"
        vector.write_text(
            json.dumps(
                {
                    "backend": "cross",
                    "status": "passed",
                    "summary": {
                        "files": 4,
                        "tests": 53,
                        "passedTests": 53,
                        "failedTests": 0,
                    },
                }
            ),
            encoding="utf-8",
        )
        acvp.write_text(
            json.dumps(
                {
                    "backend": "cross",
                    "status": "passed",
                    "summary": {"files": 1, "tests": 2, "backendMismatches": 0},
                }
            ),
            encoding="utf-8",
        )
        manifest.write_text(
            json.dumps(
                {
                    "files": [
                        {
                            "file": "sm3-request.json",
                            "sha256": "ab" * 32,
                            "vsId": 1,
                            "algorithm": "SM3",
                            "tests": 2,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return vector, acvp, manifest

    def test_report_contains_environment_results_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector, acvp, manifest = self.write_inputs(directory)
            output = directory / "report.md"
            environment = {
                "Python": "3.9.1",
                "OpenSSL": "OpenSSL test",
                "gmssl": "3.2.2",
                "Git HEAD": "abc1234",
            }
            with patch("experiment_report.collect_environment", return_value=environment):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    exit_code = experiment_report.main(
                        [
                            "--vector-summary", str(vector),
                            "--acvp-summary", str(acvp),
                            "--manifest", str(manifest),
                            "--output", str(output),
                        ]
                    )
            report = output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertIn("测试：53", report)
        self.assertIn("`" + "ab" * 32 + "`", report)
        self.assertIn("abc1234", report)
        self.assertIn("不是算法认证证书", report)

    def test_missing_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = experiment_report.main(
                    [
                        "--vector-summary", str(directory / "missing.json"),
                        "--acvp-summary", str(directory / "missing2.json"),
                        "--manifest", str(directory / "missing3.json"),
                        "--output", str(directory / "report.md"),
                    ]
                )

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)

    def test_report_cannot_overwrite_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector, acvp, manifest = self.write_inputs(directory)
            original = vector.read_bytes()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = experiment_report.main(
                    [
                        "--vector-summary", str(vector),
                        "--acvp-summary", str(acvp),
                        "--manifest", str(manifest),
                        "--output", str(vector),
                    ]
                )
            preserved = vector.read_bytes()

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
        self.assertEqual(preserved, original)


if __name__ == "__main__":
    unittest.main()
