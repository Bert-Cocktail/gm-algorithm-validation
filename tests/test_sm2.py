"""Unit and integration tests for the SM2 vector runner."""

from __future__ import annotations

import io
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import sm2_runner


PUBLIC_KEY = (
    "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
)
USER_ID = "31323334353637383132333435363738"
MESSAGE = "6d65737361676520646967657374"
SIGNATURE = (
    "3045022100962e02e24ec3266f82d846abcdac8331f74383ddb0dceaddd1f400a4dd"
    "3036af022034e8fe8e589e6cc83e93dcaa1929be66bd602dc6b8748d26c0e3f9b22e"
    "52853b"
)
RAW_SIGNATURE = (
    "962e02e24ec3266f82d846abcdac8331f74383ddb0dceaddd1f400a4dd3036af"
    "34e8fe8e589e6cc83e93dcaa1929be66bd602dc6b8748d26c0e3f9b22e52853b"
)
VECTOR_PATH = Path(__file__).parents[1] / "vectors" / "sm2.json"


def vector_document(**overrides: object) -> dict:
    test: dict[str, object] = {
        "tcId": 1,
        "operation": "verify",
        "msg": MESSAGE,
        "msgLen": len(MESSAGE) * 4,
        "publicKey": PUBLIC_KEY,
        "signature": SIGNATURE,
        "expected": True,
    }
    test.update(overrides)
    return {
        "algorithm": "SM2",
        "testGroups": [
            {
                "curve": "sm2p256v1",
                "userId": USER_ID,
                "signatureFormat": "der",
                "tests": [test],
            }
        ],
    }


class TestVectorValidation(unittest.TestCase):
    def test_repository_vectors_are_valid(self) -> None:
        tests = sm2_runner.extract_tests(sm2_runner.load_vectors(VECTOR_PATH))
        self.assertEqual(len(tests), 6)

    def test_uppercase_hex_is_normalized(self) -> None:
        tests = sm2_runner.extract_tests(
            vector_document(
                msg=MESSAGE.upper(),
                publicKey=PUBLIC_KEY.upper(),
                signature=SIGNATURE.upper(),
            )
        )
        self.assertEqual(tests[0]["msg"], MESSAGE)
        self.assertEqual(tests[0]["signature"], SIGNATURE)

    def test_duplicate_tc_id_is_rejected(self) -> None:
        document = vector_document()
        document["testGroups"][0]["tests"].append(
            document["testGroups"][0]["tests"][0].copy()
        )
        with self.assertRaisesRegex(sm2_runner.RunnerError, "duplicate tcId"):
            sm2_runner.extract_tests(document)

    def test_msg_len_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "msgLen is 8"):
            sm2_runner.extract_tests(vector_document(msgLen=8))

    def test_odd_length_message_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "whole bytes"):
            sm2_runner.extract_tests(vector_document(msg="abc", msgLen=12))

    def test_non_hex_message_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "non-hex"):
            sm2_runner.extract_tests(vector_document(msg="zz", msgLen=8))

    def test_compressed_public_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "uncompressed point"):
            sm2_runner.extract_tests(vector_document(publicKey="02" + PUBLIC_KEY[2:]))

    def test_off_curve_public_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "not on the SM2 curve"):
            sm2_runner.extract_tests(vector_document(publicKey="04" + "00" * 64))

    def test_invalid_der_signature_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "DER SEQUENCE"):
            sm2_runner.extract_tests(vector_document(signature="00"))

    def test_unsupported_curve_is_rejected(self) -> None:
        document = vector_document()
        document["testGroups"][0]["curve"] = "P-256"
        with self.assertRaisesRegex(sm2_runner.RunnerError, "sm2p256v1"):
            sm2_runner.extract_tests(document)

    def test_empty_user_id_is_rejected(self) -> None:
        document = vector_document()
        document["testGroups"][0]["userId"] = ""
        with self.assertRaisesRegex(sm2_runner.RunnerError, "must not be empty"):
            sm2_runner.extract_tests(document)

    def test_expected_must_be_boolean(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "must be a boolean"):
            sm2_runner.extract_tests(vector_document(expected=1))


class TestSignatureEncoding(unittest.TestCase):
    def test_der_to_raw(self) -> None:
        self.assertEqual(
            sm2_runner.der_signature_to_raw(bytes.fromhex(SIGNATURE)).hex(),
            RAW_SIGNATURE,
        )

    def test_raw_to_der(self) -> None:
        self.assertEqual(
            sm2_runner.raw_signature_to_der(bytes.fromhex(RAW_SIGNATURE)).hex(),
            SIGNATURE,
        )

    def test_round_trip_preserves_signature(self) -> None:
        signature = bytes.fromhex(SIGNATURE)
        self.assertEqual(
            sm2_runner.raw_signature_to_der(
                sm2_runner.der_signature_to_raw(signature)
            ),
            signature,
        )

    def test_short_raw_signature_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm2_runner.RunnerError, "exactly 64 bytes"):
            sm2_runner.raw_signature_to_der(b"\x01" * 63)

    def test_non_canonical_integer_is_rejected(self) -> None:
        malformed = bytes.fromhex("300702020001020101")
        with self.assertRaisesRegex(sm2_runner.RunnerError, "non-canonical"):
            sm2_runner.der_signature_to_raw(malformed)


class TestGmSslSm2(unittest.TestCase):
    def test_repository_vectors_match_expected_results(self) -> None:
        tests = sm2_runner.extract_tests(sm2_runner.load_vectors(VECTOR_PATH))
        for test in tests:
            with self.subTest(tcId=test["tcId"]):
                actual = sm2_runner.gmssl_sm2_verify(
                    "",
                    bytes.fromhex(test["publicKey"]),
                    bytes.fromhex(test["userId"]),
                    bytes.fromhex(test["msg"]),
                    bytes.fromhex(test["signature"]),
                )
                self.assertEqual(actual, test["expected"])


class TestOpenSslSm2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_valid_signature_when_openssl_build_supports_sm2_signatures(self) -> None:
        try:
            actual = sm2_runner.openssl_sm2_verify(
                self.openssl,
                bytes.fromhex(PUBLIC_KEY),
                bytes.fromhex(USER_ID),
                bytes.fromhex(MESSAGE),
                bytes.fromhex(SIGNATURE),
            )
        except sm2_runner.RunnerError as error:
            if "invalid digest type" in str(error):
                self.skipTest("this OpenSSL 1.1.1 build cannot run SM2 signatures")
            raise
        self.assertTrue(actual)

    def test_verification_failure_output_is_false(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout=b"Verification failure\n", stderr=b""
        )
        with patch("sm2_runner.subprocess.run", return_value=completed):
            actual = sm2_runner.openssl_sm2_verify(
                self.openssl,
                bytes.fromhex(PUBLIC_KEY),
                bytes.fromhex(USER_ID),
                bytes.fromhex(MESSAGE),
                bytes.fromhex(SIGNATURE),
            )
        self.assertFalse(actual)


class TestRunnerBehavior(unittest.TestCase):
    def setUp(self) -> None:
        self.tests = sm2_runner.extract_tests(vector_document())

    def test_matching_expected_result_passes(self) -> None:
        output = io.StringIO()
        result = sm2_runner.run_tests(
            self.tests,
            "gmssl",
            "openssl",
            gmssl_verify_fn=lambda *_args: True,
            output=output,
        )
        self.assertEqual(result, sm2_runner.EXIT_SUCCESS)
        self.assertIn("[PASS] tcId=1", output.getvalue())

    def test_wrong_result_fails(self) -> None:
        output = io.StringIO()
        result = sm2_runner.run_tests(
            self.tests,
            "gmssl",
            "openssl",
            gmssl_verify_fn=lambda *_args: False,
            output=output,
        )
        self.assertEqual(result, sm2_runner.EXIT_TEST_FAILURE)
        self.assertIn("expected=True actual=False", output.getvalue())

    def test_cross_backend_mismatch_fails(self) -> None:
        output = io.StringIO()
        result = sm2_runner.run_tests(
            self.tests,
            "cross",
            "openssl",
            openssl_verify_fn=lambda *_args: True,
            gmssl_verify_fn=lambda *_args: False,
            output=output,
        )
        self.assertEqual(result, sm2_runner.EXIT_TEST_FAILURE)
        self.assertIn("backend mismatch", output.getvalue())

    def test_missing_openssl_has_clear_error(self) -> None:
        with patch("sm2_runner.shutil.which", return_value=None):
            with self.assertRaisesRegex(sm2_runner.RunnerError, "was not found"):
                sm2_runner.resolve_openssl("definitely-missing-openssl")


if __name__ == "__main__":
    unittest.main()
