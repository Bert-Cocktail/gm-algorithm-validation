"""Unit and integration tests for the SM3 vector runner."""

from __future__ import annotations

import io
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

import runner


ABC_DIGEST = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
EMPTY_DIGEST = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
LONG_DIGEST = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"


def vector_document(msg: str, msg_len: int, md: str, tc_id: int = 1) -> dict:
    return {
        "algorithm": "SM3",
        "testGroups": [
            {"tests": [{"tcId": tc_id, "msg": msg, "msgLen": msg_len, "md": md}]}
        ],
    }


class TestVectorValidation(unittest.TestCase):
    def test_uppercase_hex_is_accepted_and_normalized(self) -> None:
        document = vector_document("616263", 24, ABC_DIGEST.upper())

        tests = runner.extract_tests(document)

        self.assertEqual(tests[0]["md"], ABC_DIGEST)

    def test_odd_length_hex_is_rejected(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "whole bytes"):
            runner.extract_tests(vector_document("123", 12, ABC_DIGEST))

    def test_non_hex_characters_are_rejected(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "non-hex"):
            runner.extract_tests(vector_document("61zz", 16, ABC_DIGEST))

    def test_msg_len_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(runner.RunnerError, "msgLen is 16"):
            runner.extract_tests(vector_document("616263", 16, ABC_DIGEST))


class TestOpenSslSm3(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_abc_standard_vector(self) -> None:
        self.assertEqual(runner.sm3_digest(self.openssl, b"abc"), ABC_DIGEST)

    def test_empty_message(self) -> None:
        self.assertEqual(runner.sm3_digest(self.openssl, b""), EMPTY_DIGEST)

    def test_long_standard_message(self) -> None:
        self.assertEqual(runner.sm3_digest(self.openssl, b"abcd" * 16), LONG_DIGEST)


class TestRunnerBehavior(unittest.TestCase):
    def test_wrong_digest_returns_test_failure(self) -> None:
        tests = runner.extract_tests(vector_document("616263", 24, "00" * 32))
        output = io.StringIO()

        result = runner.run_tests(tests, "openssl", digest_fn=lambda _cmd, _msg: ABC_DIGEST, output=output)

        self.assertEqual(result, runner.EXIT_TEST_FAILURE)
        self.assertIn("[FAIL] tcId=1", output.getvalue())
        self.assertIn("Failed: 1", output.getvalue())

    def test_missing_openssl_has_clear_error(self) -> None:
        with patch("runner.shutil.which", return_value=None):
            with self.assertRaisesRegex(runner.RunnerError, "OpenSSL was not found"):
                runner.resolve_openssl("definitely-missing-openssl")


if __name__ == "__main__":
    unittest.main()
