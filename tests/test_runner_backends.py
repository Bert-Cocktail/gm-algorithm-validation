"""Tests for selectable OpenSSL, GmSSL, and cross runner backends."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILES = (
    "sm3.json",
    "hmac-sm3.json",
    "sm4.json",
    "sm4-ctr-hmac-sm3.json",
)


class TestSelectableBackends(unittest.TestCase):
    def run_vector(self, name: str, backend: str) -> int:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return runner.main(
                [
                    str(PROJECT_ROOT / "vectors" / name),
                    "--backend",
                    backend,
                ]
            )

    def test_gmssl_backend_runs_all_vector_documents(self) -> None:
        for name in VECTOR_FILES:
            with self.subTest(name=name):
                self.assertEqual(
                    self.run_vector(name, "gmssl"), runner.EXIT_SUCCESS
                )

    def test_cross_backend_runs_all_vector_documents(self) -> None:
        for name in VECTOR_FILES:
            with self.subTest(name=name):
                self.assertEqual(
                    self.run_vector(name, "cross"), runner.EXIT_SUCCESS
                )

    def test_gmssl_backend_does_not_resolve_openssl(self) -> None:
        with patch(
            "runner.resolve_openssl",
            side_effect=AssertionError("OpenSSL must not be resolved"),
        ):
            result = self.run_vector("sm3.json", "gmssl")
        self.assertEqual(result, runner.EXIT_SUCCESS)

    def test_missing_gmssl_dependency_returns_input_error(self) -> None:
        with patch(
            "runner.importlib.import_module",
            side_effect=ImportError("gmssl is missing"),
        ):
            result = self.run_vector("sm3.json", "gmssl")
        self.assertEqual(result, runner.EXIT_INPUT_ERROR)

    def test_cross_backend_mismatch_returns_test_failure(self) -> None:
        with patch("gmssl_backend.gmssl_sm3", return_value="00" * 32):
            result = self.run_vector("sm3.json", "cross")
        self.assertEqual(result, runner.EXIT_TEST_FAILURE)


if __name__ == "__main__":
    unittest.main()
