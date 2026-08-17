"""Tests for selectable OpenSSL, GmSSL, and cross runner backends."""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import runner
import sm2_runner
import sm2_cipher


PROJECT_ROOT = Path(__file__).resolve().parents[1]
VECTOR_FILES = (
    "sm3.json",
    "hmac-sm3.json",
    "sm4.json",
    "sm4-ctr-hmac-sm3.json",
    "sm2.json",
    "sm2-encryption.json",
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
        with patch(
            "sm2_runner.openssl_sm2_verify",
            side_effect=sm2_runner.gmssl_sm2_verify,
        ), patch(
            "sm2_cipher.openssl_encrypt",
            side_effect=lambda command, key, value: sm2_cipher.convert_ciphertext(
                sm2_cipher.gmssl_encrypt("", key, value), "c1c3c2", "der"
            ),
        ), patch(
            "sm2_cipher.openssl_decrypt",
            side_effect=lambda command, key, value: sm2_cipher.gmssl_decrypt(
                "", key, sm2_cipher.convert_ciphertext(value, "der", "c1c3c2")
            ),
        ):
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
        errors = io.StringIO()
        with patch("gmssl_backend.gmssl_sm3", return_value="00" * 32):
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                result = runner.main(
                    [str(PROJECT_ROOT / "vectors" / "sm3.json"), "--backend", "cross"]
                )
        self.assertEqual(result, runner.EXIT_TEST_FAILURE)
        self.assertIn("tcId=1", errors.getvalue())
        self.assertIn("OpenSSL=66c7", errors.getvalue())
        self.assertIn("GmSSL=0000", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
