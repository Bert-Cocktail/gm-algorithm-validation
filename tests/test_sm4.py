"""Unit and integration tests for the SM4 vector runner."""

from __future__ import annotations

import io
import shutil
import unittest
from unittest.mock import patch

import sm4_runner


KEY = "0123456789abcdeffedcba9876543210"
PLAINTEXT = "0123456789abcdeffedcba9876543210"
CIPHERTEXT = "681edf34d206965e86b3e94f536e4246"
IV = "000102030405060708090a0b0c0d0e0f"
CTR_PLAINTEXT = PLAINTEXT + "01020304"
CTR_CIPHERTEXT = "07bbd906b40da542d4514d1a97fccb7a6e050e4f"


def vector_document(
    *,
    mode: str = "ECB",
    direction: str = "encrypt",
    key: str = KEY,
    pt: str = PLAINTEXT,
    ct: str = CIPHERTEXT,
    iv: str | None = None,
    tc_id: int = 1,
) -> dict:
    test = {"tcId": tc_id, "key": key, "pt": pt, "ct": ct}
    if iv is not None:
        test["iv"] = iv
    return {
        "algorithm": "SM4",
        "testGroups": [
            {"mode": mode, "direction": direction, "tests": [test]}
        ],
    }


class TestVectorValidation(unittest.TestCase):
    def test_uppercase_hex_is_accepted_and_normalized(self) -> None:
        tests = sm4_runner.extract_tests(
            vector_document(key=KEY.upper(), pt=PLAINTEXT.upper(), ct=CIPHERTEXT.upper())
        )

        self.assertEqual(tests[0]["key"], KEY)
        self.assertEqual(tests[0]["pt"], PLAINTEXT)
        self.assertEqual(tests[0]["ct"], CIPHERTEXT)

    def test_short_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "32 hex characters"):
            sm4_runner.extract_tests(vector_document(key="00" * 15))

    def test_long_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "32 hex characters"):
            sm4_runner.extract_tests(vector_document(key="00" * 17))

    def test_non_hex_key_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "non-hex"):
            sm4_runner.extract_tests(vector_document(key="zz" * 16))

    def test_non_block_aligned_plaintext_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "16-byte SM4 blocks"):
            sm4_runner.extract_tests(vector_document(pt="00" * 15))

    def test_duplicate_tc_id_is_rejected(self) -> None:
        document = vector_document()
        duplicate_group = {
            "mode": "ECB",
            "direction": "decrypt",
            "tests": [
                {"tcId": 1, "key": KEY, "pt": PLAINTEXT, "ct": CIPHERTEXT}
            ],
        }
        document["testGroups"].append(duplicate_group)

        with self.assertRaisesRegex(sm4_runner.RunnerError, "duplicate tcId"):
            sm4_runner.extract_tests(document)

    def test_unsupported_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "unsupported mode 'GCM'"):
            sm4_runner.extract_tests(vector_document(mode="GCM"))

    def test_cbc_without_iv_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "'iv' must be a string"):
            sm4_runner.extract_tests(vector_document(mode="CBC"))

    def test_ctr_without_iv_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "'iv' must be a string"):
            sm4_runner.extract_tests(
                vector_document(mode="CTR", pt=CTR_PLAINTEXT, ct=CTR_CIPHERTEXT)
            )

    def test_ctr_accepts_non_block_aligned_data(self) -> None:
        tests = sm4_runner.extract_tests(
            vector_document(
                mode="CTR", pt=CTR_PLAINTEXT, ct=CTR_CIPHERTEXT, iv=IV
            )
        )

        self.assertEqual(tests[0]["pt"], CTR_PLAINTEXT)

    def test_ctr_empty_data_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "must not be empty"):
            sm4_runner.extract_tests(
                vector_document(mode="CTR", pt="", ct="", iv=IV)
            )

    def test_ctr_short_iv_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "32 hex characters"):
            sm4_runner.extract_tests(
                vector_document(
                    mode="CTR", pt=CTR_PLAINTEXT, ct=CTR_CIPHERTEXT, iv="00" * 15
                )
            )

    def test_ecb_with_iv_is_rejected(self) -> None:
        with self.assertRaisesRegex(sm4_runner.RunnerError, "must not include an IV"):
            sm4_runner.extract_tests(vector_document(iv=IV))


class TestOpenSslSm4(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_ecb_standard_vector_encrypt(self) -> None:
        actual = sm4_runner.sm4_crypt(
            self.openssl,
            "ECB",
            "encrypt",
            KEY,
            None,
            bytes.fromhex(PLAINTEXT),
        )

        self.assertEqual(actual.hex(), CIPHERTEXT)

    def test_ecb_standard_vector_decrypt(self) -> None:
        actual = sm4_runner.sm4_crypt(
            self.openssl,
            "ECB",
            "decrypt",
            KEY,
            None,
            bytes.fromhex(CIPHERTEXT),
        )

        self.assertEqual(actual.hex(), PLAINTEXT)

    def test_cbc_encrypt_decrypt_round_trip(self) -> None:
        plaintext = bytes.fromhex(PLAINTEXT * 2)
        ciphertext = sm4_runner.sm4_crypt(
            self.openssl, "CBC", "encrypt", KEY, IV, plaintext
        )
        recovered = sm4_runner.sm4_crypt(
            self.openssl, "CBC", "decrypt", KEY, IV, ciphertext
        )

        self.assertNotEqual(ciphertext, plaintext)
        self.assertEqual(recovered, plaintext)

    def test_ctr_non_block_aligned_encrypt_decrypt(self) -> None:
        plaintext = bytes.fromhex(CTR_PLAINTEXT)
        ciphertext = sm4_runner.sm4_crypt(
            self.openssl, "CTR", "encrypt", KEY, IV, plaintext
        )
        recovered = sm4_runner.sm4_crypt(
            self.openssl, "CTR", "decrypt", KEY, IV, ciphertext
        )

        self.assertEqual(ciphertext.hex(), CTR_CIPHERTEXT)
        self.assertEqual(recovered, plaintext)


class TestRunnerBehavior(unittest.TestCase):
    def test_wrong_ciphertext_returns_test_failure(self) -> None:
        tests = sm4_runner.extract_tests(vector_document(ct="00" * 16))
        output = io.StringIO()

        result = sm4_runner.run_tests(
            tests,
            "openssl",
            crypt_fn=lambda _cmd, _mode, _direction, _key, _iv, _data: bytes.fromhex(
                CIPHERTEXT
            ),
            output=output,
        )

        self.assertEqual(result, sm4_runner.EXIT_TEST_FAILURE)
        self.assertIn("[FAIL] tcId=1 mode=ECB direction=encrypt", output.getvalue())
        self.assertIn("Failed: 1", output.getvalue())

    def test_missing_openssl_has_clear_error(self) -> None:
        with patch("sm4_runner.shutil.which", return_value=None):
            with self.assertRaisesRegex(
                sm4_runner.RunnerError, "OpenSSL was not found"
            ):
                sm4_runner.resolve_openssl("definitely-missing-openssl")


if __name__ == "__main__":
    unittest.main()
