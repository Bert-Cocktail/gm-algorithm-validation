"""Tests for structured JSON reports produced by the unified runner."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILES = {
    "sm3.json": ("SM3", 15),
    "hmac-sm3.json": ("HMAC-SM3", 4),
    "sm4.json": ("SM4", 28),
    "sm4-ctr-hmac-sm3.json": ("SM4-CTR-HMAC-SM3", 6),
}


class TestStructuredResults(unittest.TestCase):
    def run_quietly(self, arguments: list[str]) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return runner.main(arguments)

    def test_success_reports_for_all_algorithms(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            for vector_name, (algorithm, total) in VECTOR_FILES.items():
                with self.subTest(vector=vector_name):
                    result_path = directory / f"{vector_name}.result.json"
                    exit_code = self.run_quietly(
                        [
                            str(PROJECT_ROOT / "vectors" / vector_name),
                            "--result-json",
                            str(result_path),
                        ]
                    )
                    report = json.loads(result_path.read_text(encoding="utf-8"))

                    self.assertEqual(exit_code, runner.EXIT_SUCCESS)
                    self.assertEqual(report["schemaVersion"], 1)
                    self.assertEqual(report["algorithm"], algorithm)
                    self.assertEqual(report["backend"], "openssl")
                    self.assertEqual(report["status"], "passed")
                    self.assertEqual(report["exitCode"], 0)
                    self.assertEqual(
                        report["summary"],
                        {"total": total, "passed": total, "failed": 0},
                    )
                    self.assertEqual(len(report["tests"]), total)
                    self.assertTrue(
                        all(test["status"] == "passed" for test in report["tests"])
                    )

    def test_failed_vector_records_expected_and_actual(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector_path = directory / "failed-sm3.json"
            result_path = directory / "result.json"
            document = json.loads(
                (PROJECT_ROOT / "vectors" / "sm3.json").read_text(encoding="utf-8")
            )
            document["testGroups"][0]["tests"][0]["md"] = "00" * 32
            vector_path.write_text(json.dumps(document), encoding="utf-8")

            exit_code = self.run_quietly(
                [str(vector_path), "--result-json", str(result_path)]
            )
            report = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, runner.EXIT_TEST_FAILURE)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["tests"][0]["status"], "failed")
        self.assertEqual(report["tests"][0]["expected"], "00" * 32)
        self.assertNotEqual(
            report["tests"][0]["actual"], report["tests"][0]["expected"]
        )

    def test_input_error_is_written_as_error_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector_path = directory / "unsupported.json"
            result_path = directory / "result.json"
            vector_path.write_text(
                json.dumps({"algorithm": "SM2", "testGroups": []}),
                encoding="utf-8",
            )

            exit_code = self.run_quietly(
                [str(vector_path), "--result-json", str(result_path)]
            )
            report = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, runner.EXIT_INPUT_ERROR)
        self.assertEqual(report["status"], "error")
        self.assertIsNone(report["summary"])
        self.assertEqual(report["tests"], [])
        self.assertEqual(report["error"]["type"], "input_error")
        self.assertIn("unsupported algorithm", report["error"]["message"])

    def test_result_path_cannot_overwrite_vector_file(self) -> None:
        vector_path = PROJECT_ROOT / "vectors" / "sm3.json"
        original = vector_path.read_bytes()

        exit_code = self.run_quietly(
            [str(vector_path), "--result-json", str(vector_path)]
        )

        self.assertEqual(exit_code, runner.EXIT_INPUT_ERROR)
        self.assertEqual(vector_path.read_bytes(), original)

    def test_existing_result_file_is_atomically_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            result_path = Path(directory_name) / "result.json"
            result_path.write_text("old result", encoding="utf-8")

            exit_code = self.run_quietly(
                [
                    str(PROJECT_ROOT / "vectors" / "sm3.json"),
                    "--backend",
                    "gmssl",
                    "--result-json",
                    str(result_path),
                ]
            )
            report = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, runner.EXIT_SUCCESS)
        self.assertEqual(report["backend"], "gmssl")

    def test_backend_mismatch_report_identifies_test_and_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            result_path = Path(directory_name) / "mismatch.json"
            with patch("gmssl_backend.gmssl_sm3", return_value="00" * 32):
                exit_code = self.run_quietly(
                    [
                        str(PROJECT_ROOT / "vectors" / "sm3.json"),
                        "--backend", "cross",
                        "--result-json", str(result_path),
                    ]
                )
            report = json.loads(result_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, runner.EXIT_TEST_FAILURE)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["summary"], {"total": 15, "passed": 0, "failed": 15})
        self.assertEqual(report["error"]["type"], "backend_mismatches")
        self.assertEqual(report["error"]["count"], 15)
        self.assertEqual(len(report["error"]["mismatches"]), 15)
        first = report["error"]["mismatches"][0]
        last = report["error"]["mismatches"][-1]
        self.assertEqual(first["tcId"], 1)
        self.assertEqual(last["tcId"], 15)
        self.assertEqual(first["operation"], "SM3")
        self.assertTrue(first["openssl"].startswith("66c7"))
        self.assertEqual(first["gmssl"], "00" * 32)


if __name__ == "__main__":
    unittest.main()
