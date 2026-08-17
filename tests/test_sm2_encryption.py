"""Tests for SM2 encryption and ciphertext conversion."""

from __future__ import annotations

import io
import unittest
from pathlib import Path
from unittest.mock import patch

from gmssl import sm2

import sm2_cipher
import sm2_encryption_runner


PRIVATE_KEY = (1).to_bytes(32, "big")
PUBLIC_KEY = bytes.fromhex("04" + sm2.default_ecc_table["g"])
VECTOR_PATH = Path(__file__).parents[1] / "vectors" / "sm2-encryption.json"


class TestCiphertextFormats(unittest.TestCase):
    def setUp(self) -> None:
        with patch("gmssl.func.random_hex", return_value=f"{2:064x}"):
            self.raw = sm2_cipher.gmssl_encrypt("", PUBLIC_KEY, b"abc")

    def test_all_formats_round_trip(self) -> None:
        for target in sm2_cipher.SUPPORTED_FORMATS:
            with self.subTest(target=target):
                converted = sm2_cipher.convert_ciphertext(self.raw, "c1c3c2", target)
                restored = sm2_cipher.convert_ciphertext(converted, target, "c1c3c2")
                self.assertEqual(restored, self.raw)

    def test_gmssl_decrypt_checks_c3(self) -> None:
        tampered = bytearray(self.raw)
        tampered[65] ^= 1
        with self.assertRaisesRegex(sm2_cipher.CipherError, "integrity"):
            sm2_cipher.gmssl_decrypt("", PRIVATE_KEY, bytes(tampered))

    def test_off_curve_c1_is_rejected(self) -> None:
        malformed = b"\x04" + b"\x00" * 64 + self.raw[65:]
        with self.assertRaisesRegex(sm2_cipher.CipherError, "not a point"):
            sm2_cipher.gmssl_decrypt("", PRIVATE_KEY, malformed)

    def test_noncanonical_der_length_is_rejected(self) -> None:
        der = sm2_cipher.convert_ciphertext(self.raw, "c1c3c2", "der")
        malformed = b"\x30\x81" + bytes([der[1]]) + der[2:]
        with self.assertRaisesRegex(sm2_cipher.CipherError, "non-canonical"):
            sm2_cipher.parse_ciphertext(malformed, "der")


class TestEncryptionVectors(unittest.TestCase):
    def test_repository_vectors_are_valid(self) -> None:
        import json

        document = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        tests = sm2_encryption_runner.extract_tests(document)
        self.assertEqual(len(tests), 5)

    def test_repository_vectors_pass_gmssl(self) -> None:
        import json

        tests = sm2_encryption_runner.extract_tests(
            json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
        )
        output = io.StringIO()
        self.assertEqual(
            sm2_encryption_runner.run_tests(tests, "gmssl", "", output=output),
            sm2_encryption_runner.EXIT_SUCCESS,
        )
        self.assertIn("Passed: 5", output.getvalue())

    def test_duplicate_id_is_rejected(self) -> None:
        document = {
            "algorithm": "SM2-ENCRYPTION",
            "testGroups": [{"curve": "sm2p256v1", "tests": []}],
        }
        sample = {
            "tcId": 1, "operation": "encryptRoundTrip",
            "privateKey": PRIVATE_KEY.hex(), "publicKey": PUBLIC_KEY.hex(), "msg": "61",
        }
        document["testGroups"][0]["tests"] = [sample, sample.copy()]
        with self.assertRaisesRegex(sm2_encryption_runner.RunnerError, "duplicate"):
            sm2_encryption_runner.extract_tests(document)


if __name__ == "__main__":
    unittest.main()
