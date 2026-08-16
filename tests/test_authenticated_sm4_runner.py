"""Tests for authenticated SM4 vector parsing and execution."""

from __future__ import annotations

import io
import json
import shutil
import unittest
from pathlib import Path

import authenticated_sm4_runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_document() -> dict:
    return json.loads(
        (PROJECT_ROOT / "vectors" / "sm4-ctr-hmac-sm3.json").read_text(
            encoding="utf-8"
        )
    )


class TestAuthenticatedVectorValidation(unittest.TestCase):
    def test_vector_is_normalized(self) -> None:
        document = load_document()
        test = document["testGroups"][0]["tests"][0]
        test["iv"] = test["iv"].upper()
        extracted = authenticated_sm4_runner.extract_tests(document)
        self.assertEqual(extracted[0]["iv"], test["iv"].lower())

    def test_duplicate_id_is_rejected(self) -> None:
        document = load_document()
        test = dict(document["testGroups"][0]["tests"][0])
        document["testGroups"][0]["tests"].append(test)
        with self.assertRaisesRegex(authenticated_sm4_runner.RunnerError, "duplicate"):
            authenticated_sm4_runner.extract_tests(document)

    def test_invalid_key_and_iv_are_rejected(self) -> None:
        document = load_document()
        test = document["testGroups"][0]["tests"][0]
        test["sm4Key"] = "00"
        with self.assertRaisesRegex(authenticated_sm4_runner.RunnerError, "16 bytes"):
            authenticated_sm4_runner.extract_tests(document)

        document = load_document()
        document["testGroups"][0]["tests"][0]["iv"] = "00"
        with self.assertRaisesRegex(authenticated_sm4_runner.RunnerError, "16 bytes"):
            authenticated_sm4_runner.extract_tests(document)

    def test_plaintext_ciphertext_length_mismatch_is_rejected(self) -> None:
        document = load_document()
        document["testGroups"][0]["tests"][0]["ct"] += "00"
        with self.assertRaisesRegex(authenticated_sm4_runner.RunnerError, "same length"):
            authenticated_sm4_runner.extract_tests(document)


class TestAuthenticatedVectorExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_fixed_vector_passes(self) -> None:
        tests = authenticated_sm4_runner.extract_tests(load_document())
        result = authenticated_sm4_runner.run_tests(
            tests, self.openssl, output=io.StringIO()
        )
        self.assertEqual(result, authenticated_sm4_runner.EXIT_SUCCESS)

    def test_wrong_expected_tag_fails(self) -> None:
        document = load_document()
        document["testGroups"][0]["tests"][0]["tag"] = "00" * 32
        tests = authenticated_sm4_runner.extract_tests(document)
        output = io.StringIO()
        result = authenticated_sm4_runner.run_tests(
            tests, self.openssl, output=output
        )
        self.assertEqual(result, authenticated_sm4_runner.EXIT_TEST_FAILURE)
        self.assertIn("[FAIL]", output.getvalue())


if __name__ == "__main__":
    unittest.main()
