"""Tests for running every vector file and writing aggregate reports."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VECTOR_NAMES = (
    "sm3.json",
    "hmac-sm3.json",
    "sm4.json",
    "sm4-ctr-hmac-sm3.json",
)


class TestBatchRunner(unittest.TestCase):
    def run_batch(
        self, vector_dir: Path, result_dir: Path, backend: str = "openssl"
    ) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            exit_code = runner.main(
                [
                    "--all",
                    "--vector-dir", str(vector_dir),
                    "--backend", backend,
                    "--result-dir", str(result_dir),
                ]
            )
        return exit_code, output.getvalue(), errors.getvalue()

    def copy_vectors(self, target: Path) -> None:
        target.mkdir()
        for name in VECTOR_NAMES:
            shutil.copyfile(PROJECT_ROOT / "vectors" / name, target / name)

    def test_all_vectors_generate_individual_and_summary_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            result_dir = directory / "results"
            exit_code, output, errors = self.run_batch(
                PROJECT_ROOT / "vectors", result_dir, "cross"
            )
            summary = json.loads(
                (result_dir / "summary.json").read_text(encoding="utf-8")
            )

            self.assertEqual(exit_code, runner.EXIT_SUCCESS)
            self.assertEqual(errors, "")
            self.assertIn("Files=4", output)
            self.assertIn("Tests=53", output)
            self.assertEqual(summary["backend"], "cross")
            self.assertEqual(summary["status"], "passed")
            self.assertEqual(
                summary["summary"],
                {
                    "files": 4,
                    "passedFiles": 4,
                    "failedFiles": 0,
                    "errorFiles": 0,
                    "tests": 53,
                    "passedTests": 53,
                    "failedTests": 0,
                },
            )
            self.assertEqual(len(summary["files"]), 4)
            for name in VECTOR_NAMES:
                self.assertTrue(
                    (result_dir / f"{Path(name).stem}-cross.json").is_file()
                )

    def test_test_failure_does_not_stop_later_vector_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector_dir = directory / "vectors"
            result_dir = directory / "results"
            self.copy_vectors(vector_dir)
            sm3_path = vector_dir / "sm3.json"
            sm3 = json.loads(sm3_path.read_text(encoding="utf-8"))
            sm3["testGroups"][0]["tests"][0]["md"] = "00" * 32
            sm3_path.write_text(json.dumps(sm3), encoding="utf-8")

            exit_code, _output, _errors = self.run_batch(vector_dir, result_dir)
            summary = json.loads(
                (result_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exit_code, runner.EXIT_TEST_FAILURE)
            self.assertEqual(summary["summary"]["files"], 4)
            self.assertEqual(summary["summary"]["passedFiles"], 3)
            self.assertEqual(summary["summary"]["failedFiles"], 1)
            self.assertTrue((result_dir / "sm4-openssl.json").is_file())

    def test_input_error_has_priority_and_other_files_continue(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            vector_dir = directory / "vectors"
            result_dir = directory / "results"
            self.copy_vectors(vector_dir)
            (vector_dir / "unsupported.json").write_text(
                json.dumps({"algorithm": "SM2", "testGroups": []}),
                encoding="utf-8",
            )

            exit_code, _output, errors = self.run_batch(vector_dir, result_dir)
            summary = json.loads(
                (result_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exit_code, runner.EXIT_INPUT_ERROR)
            self.assertIn("unsupported algorithm", errors)
            self.assertEqual(summary["summary"]["files"], 5)
            self.assertEqual(summary["summary"]["passedFiles"], 4)
            self.assertEqual(summary["summary"]["errorFiles"], 1)
            self.assertTrue((result_dir / "unsupported-openssl.json").is_file())

    def test_gmssl_batch_does_not_resolve_openssl(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            with patch(
                "runner.resolve_openssl",
                side_effect=AssertionError("OpenSSL must not be resolved"),
            ):
                exit_code, _output, _errors = self.run_batch(
                    PROJECT_ROOT / "vectors",
                    Path(directory_name) / "results",
                    "gmssl",
                )

        self.assertEqual(exit_code, runner.EXIT_SUCCESS)

    def test_result_directory_cannot_equal_vector_directory(self) -> None:
        exit_code, _output, errors = self.run_batch(
            PROJECT_ROOT / "vectors", PROJECT_ROOT / "vectors"
        )

        self.assertEqual(exit_code, runner.EXIT_INPUT_ERROR)
        self.assertIn("must differ", errors)


if __name__ == "__main__":
    unittest.main()
