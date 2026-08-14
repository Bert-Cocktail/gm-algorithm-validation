"""Tests for HMAC-SM3 vector validation."""

from __future__ import annotations

import io
import shutil
import unittest

import hmac_sm3_runner


KEY = "00112233445566778899aabbccddeeff"
ABC_TAG = "0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d"


def document(test: dict[str, object]) -> dict[str, object]:
    return {"algorithm": "HMAC-SM3", "testGroups": [{"tests": [test]}]}


def vector(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "tcId": 1, "key": KEY, "msg": "616263", "msgLen": 24, "tag": ABC_TAG
    }
    value.update(changes)
    return value


class TestHmacSm3Runner(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_known_tag(self) -> None:
        self.assertEqual(
            hmac_sm3_runner.hmac_sm3(self.openssl, KEY, b"abc"), ABC_TAG
        )

    def test_empty_message(self) -> None:
        tag = hmac_sm3_runner.hmac_sm3(self.openssl, KEY, b"")
        self.assertEqual(len(tag), 64)

    def test_wrong_tag_fails(self) -> None:
        tests = hmac_sm3_runner.extract_tests(document(vector(tag="00" * 32)))
        result = hmac_sm3_runner.run_tests(
            tests, self.openssl, output=io.StringIO()
        )
        self.assertEqual(result, hmac_sm3_runner.EXIT_TEST_FAILURE)

    def test_rejects_empty_key(self) -> None:
        with self.assertRaisesRegex(hmac_sm3_runner.RunnerError, "must not be empty"):
            hmac_sm3_runner.extract_tests(document(vector(key="")))

    def test_rejects_invalid_message(self) -> None:
        with self.assertRaisesRegex(hmac_sm3_runner.RunnerError, "non-hex"):
            hmac_sm3_runner.extract_tests(document(vector(msg="zz", msgLen=8)))

    def test_rejects_invalid_tag_length(self) -> None:
        with self.assertRaisesRegex(hmac_sm3_runner.RunnerError, "64 hex"):
            hmac_sm3_runner.extract_tests(document(vector(tag="00")))

    def test_rejects_wrong_message_length(self) -> None:
        with self.assertRaisesRegex(hmac_sm3_runner.RunnerError, "msgLen"):
            hmac_sm3_runner.extract_tests(document(vector(msgLen=23)))

    def test_rejects_duplicate_ids(self) -> None:
        value = document(vector())
        value["testGroups"][0]["tests"].append(vector())  # type: ignore[index]
        with self.assertRaisesRegex(hmac_sm3_runner.RunnerError, "duplicate tcId"):
            hmac_sm3_runner.extract_tests(value)


if __name__ == "__main__":
    unittest.main()
