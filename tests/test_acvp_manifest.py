"""Tests for reproducible ACVP request manifests."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import acvp_adapter
import acvp_manifest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "acvp" / "requests"


class TestAcvpManifest(unittest.TestCase):
    def test_manifest_records_all_samples_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "manifest.json"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = acvp_manifest.main(
                    ["--request-dir", str(SAMPLES), "--output", str(output)]
                )
            manifest = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertEqual(manifest["summary"], {"files": 4, "tests": 9})
        self.assertEqual(
            [item["file"] for item in manifest["files"]],
            [
                "hmac-sm3-request.json",
                "sm2-request.json",
                "sm3-request.json",
                "sm4-request.json",
            ],
        )
        for item in manifest["files"]:
            expected = hashlib.sha256((SAMPLES / item["file"]).read_bytes()).hexdigest()
            self.assertEqual(item["sha256"], expected)

    def test_duplicate_vs_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            source = SAMPLES / "sm3-request.json"
            shutil.copyfile(source, directory / "a-request.json")
            shutil.copyfile(source, directory / "b-request.json")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = acvp_manifest.main(
                    [
                        "--request-dir",
                        str(directory),
                        "--output",
                        str(directory / "manifest.json"),
                    ]
                )

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)

    def test_empty_request_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = acvp_manifest.main(
                    [
                        "--request-dir",
                        str(directory),
                        "--output",
                        str(directory / "manifest.json"),
                    ]
                )

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)

    def test_manifest_cannot_overwrite_request(self) -> None:
        request_path = SAMPLES / "sm3-request.json"
        original = request_path.read_bytes()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            exit_code = acvp_manifest.main(
                ["--request-dir", str(SAMPLES), "--output", str(request_path)]
            )

        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
        self.assertEqual(request_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
