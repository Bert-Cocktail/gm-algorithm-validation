"""Tests for batch ACVP-style request processing."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import acvp_adapter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_REQUESTS = PROJECT_ROOT / "acvp" / "requests"


class TestAcvpBatch(unittest.TestCase):
    def run_batch(self, request_dir: Path, response_dir: Path) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return acvp_adapter.main(
                [
                    "--all",
                    "--request-dir",
                    str(request_dir),
                    "--response-dir",
                    str(response_dir),
                    "--backend",
                    "cross",
                ]
            )

    def copy_sample(self, name: str, destination: Path) -> Path:
        path = destination / name
        shutil.copyfile(SAMPLE_REQUESTS / name, path)
        return path

    def test_all_sample_requests_generate_responses_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            request_dir = root / "requests"
            response_dir = root / "responses"
            request_dir.mkdir()
            for name in (
                "sm3-request.json",
                "hmac-sm3-request.json",
                "sm4-request.json",
            ):
                self.copy_sample(name, request_dir)

            exit_code = self.run_batch(request_dir, response_dir)
            summary = json.loads(
                (response_dir / "summary.json").read_text(encoding="utf-8")
            )

            self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
            self.assertEqual(summary["status"], "passed")
            self.assertEqual(
                summary["summary"],
                {
                    "files": 3,
                    "passedFiles": 3,
                    "failedFiles": 0,
                    "errorFiles": 0,
                    "tests": 5,
                    "backendMismatches": 0,
                },
            )
            self.assertTrue((response_dir / "sm3-response.json").is_file())
            self.assertTrue((response_dir / "hmac-sm3-response.json").is_file())
            self.assertTrue((response_dir / "sm4-response.json").is_file())

    def test_invalid_request_does_not_stop_later_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            request_dir = root / "requests"
            response_dir = root / "responses"
            request_dir.mkdir()
            (request_dir / "a-bad-request.json").write_text("{}", encoding="utf-8")
            self.copy_sample("sm3-request.json", request_dir)

            exit_code = self.run_batch(request_dir, response_dir)
            summary = json.loads(
                (response_dir / "summary.json").read_text(encoding="utf-8")
            )

            self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
            self.assertEqual(summary["summary"]["errorFiles"], 1)
            self.assertEqual(summary["summary"]["passedFiles"], 1)
            self.assertTrue((response_dir / "sm3-response.json").is_file())

    def test_cross_mismatches_are_counted_in_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            request_dir = root / "requests"
            response_dir = root / "responses"
            request_dir.mkdir()
            self.copy_sample("sm3-request.json", request_dir)

            with patch("gmssl_backend.gmssl_sm3", return_value="00" * 32):
                exit_code = self.run_batch(request_dir, response_dir)
            summary = json.loads(
                (response_dir / "summary.json").read_text(encoding="utf-8")
            )

            self.assertEqual(exit_code, acvp_adapter.EXIT_TEST_FAILURE)
            self.assertEqual(summary["summary"]["failedFiles"], 1)
            self.assertEqual(summary["summary"]["backendMismatches"], 2)

    def test_duplicate_vs_id_across_files_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            root = Path(directory_name)
            request_dir = root / "requests"
            response_dir = root / "responses"
            request_dir.mkdir()
            source = SAMPLE_REQUESTS / "sm3-request.json"
            shutil.copyfile(source, request_dir / "a-request.json")
            shutil.copyfile(source, request_dir / "b-request.json")

            exit_code = self.run_batch(request_dir, response_dir)
            summary = json.loads(
                (response_dir / "summary.json").read_text(encoding="utf-8")
            )

            self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
            self.assertEqual(summary["summary"]["passedFiles"], 1)
            self.assertEqual(summary["summary"]["errorFiles"], 1)

    def test_request_and_response_directories_must_differ(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self.copy_sample("sm3-request.json", directory)

            exit_code = self.run_batch(directory, directory)

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)


if __name__ == "__main__":
    unittest.main()
