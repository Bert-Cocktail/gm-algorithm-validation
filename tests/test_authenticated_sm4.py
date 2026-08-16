"""Tests for authenticated SM4 key, package, and encoding rules."""

from __future__ import annotations

import unittest
import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import authenticated_sm4


SM4_KEY = "0123456789abcdeffedcba9876543210"
HMAC_KEY = (
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9bacbdcedfe0f"
)
IV = "000102030405060708090a0b0c0d0e0f"
TAG = "00" * 32
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def package(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "algorithm": "SM4-CTR-HMAC-SM3",
        "iv": IV,
        "ciphertext": "616263",
        "tag": TAG,
    }
    value.update(changes)
    return value


class TestKeyRules(unittest.TestCase):
    def test_keys_are_normalized(self) -> None:
        actual = authenticated_sm4.validate_keys(SM4_KEY.upper(), HMAC_KEY.upper())
        self.assertEqual(actual, (SM4_KEY, HMAC_KEY))

    def test_sm4_key_must_be_16_bytes(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "16 bytes"):
            authenticated_sm4.validate_keys("00" * 15, HMAC_KEY)

    def test_hmac_key_must_be_32_bytes(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "32 bytes"):
            authenticated_sm4.validate_keys(SM4_KEY, "00" * 16)


class TestPackageFormat(unittest.TestCase):
    def test_package_is_normalized(self) -> None:
        normalized = authenticated_sm4.validate_package(
            package(iv=IV.upper(), ciphertext="A0", tag=("AB" * 32))
        )
        self.assertEqual(normalized["iv"], IV)
        self.assertEqual(normalized["ciphertext"], "a0")
        self.assertEqual(normalized["tag"], "ab" * 32)

    def test_empty_ciphertext_is_allowed(self) -> None:
        normalized = authenticated_sm4.validate_package(package(ciphertext=""))
        self.assertEqual(normalized["ciphertext"], "")

    def test_missing_field_is_rejected(self) -> None:
        value = package()
        del value["tag"]
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "missing.*tag"):
            authenticated_sm4.validate_package(value)

    def test_unknown_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "unknown.*note"):
            authenticated_sm4.validate_package(package(note="not authenticated"))

    def test_wrong_version_and_algorithm_are_rejected(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "version"):
            authenticated_sm4.validate_package(package(version=2))
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "algorithm"):
            authenticated_sm4.validate_package(package(algorithm="SM4-CTR"))

    def test_iv_and_tag_lengths_are_checked(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "16 bytes"):
            authenticated_sm4.validate_package(package(iv="00" * 15))
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "32 bytes"):
            authenticated_sm4.validate_package(package(tag="00" * 31))


class TestAuthenticatedEncoding(unittest.TestCase):
    def test_encoding_has_fixed_field_order_and_big_endian_length(self) -> None:
        actual = authenticated_sm4.build_authenticated_data(
            1,
            authenticated_sm4.ALGORITHM,
            bytes.fromhex(IV),
            b"abc",
        )
        expected = (
            b"GMENC"
            + b"\x01"
            + b"SM4-CTR-HMAC-SM3"
            + bytes.fromhex(IV)
            + b"\x00\x00\x00\x00\x00\x00\x00\x03"
            + b"abc"
        )
        self.assertEqual(actual, expected)

    def test_tag_is_not_part_of_authenticated_data(self) -> None:
        first = authenticated_sm4.package_authenticated_data(package(tag="00" * 32))
        second = authenticated_sm4.package_authenticated_data(package(tag="ff" * 32))
        self.assertEqual(first, second)

    def test_iv_and_ciphertext_change_authenticated_data(self) -> None:
        baseline = authenticated_sm4.package_authenticated_data(package())
        changed_iv = authenticated_sm4.package_authenticated_data(
            package(iv="01" + IV[2:])
        )
        changed_ciphertext = authenticated_sm4.package_authenticated_data(
            package(ciphertext="616264")
        )
        self.assertNotEqual(baseline, changed_iv)
        self.assertNotEqual(baseline, changed_ciphertext)


class TestAuthenticatedEncryption(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def encrypt(self, plaintext: bytes = b"abc") -> authenticated_sm4.AuthenticatedPackage:
        return authenticated_sm4.encrypt_and_authenticate(
            self.openssl,
            SM4_KEY,
            HMAC_KEY,
            plaintext,
            iv=bytes.fromhex(IV),
        )

    def test_fixed_vector_matches_json_and_decrypts(self) -> None:
        document = json.loads(
            (PROJECT_ROOT / "vectors" / "sm4-ctr-hmac-sm3.json").read_text(
                encoding="utf-8"
            )
        )
        test = document["testGroups"][0]["tests"][0]
        actual = authenticated_sm4.encrypt_and_authenticate(
            self.openssl,
            test["sm4Key"],
            test["hmacKey"],
            bytes.fromhex(test["pt"]),
            iv=bytes.fromhex(test["iv"]),
        )
        self.assertEqual(actual["ciphertext"], test["ct"])
        self.assertEqual(actual["tag"], test["tag"])
        self.assertEqual(
            authenticated_sm4.verify_and_decrypt(
                self.openssl, test["sm4Key"], test["hmacKey"], actual
            ),
            bytes.fromhex(test["pt"]),
        )

    def test_empty_and_non_block_aligned_plaintext_round_trip(self) -> None:
        for plaintext in (b"", b"abc", bytes(range(20))):
            with self.subTest(length=len(plaintext)):
                value = authenticated_sm4.encrypt_and_authenticate(
                    self.openssl, SM4_KEY, HMAC_KEY, plaintext
                )
                recovered = authenticated_sm4.verify_and_decrypt(
                    self.openssl, SM4_KEY, HMAC_KEY, value
                )
                self.assertEqual(recovered, plaintext)

    def test_automatic_iv_is_fresh(self) -> None:
        first = authenticated_sm4.encrypt_and_authenticate(
            self.openssl, SM4_KEY, HMAC_KEY, b"same message"
        )
        second = authenticated_sm4.encrypt_and_authenticate(
            self.openssl, SM4_KEY, HMAC_KEY, b"same message"
        )
        self.assertNotEqual(first["iv"], second["iv"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])
        self.assertNotEqual(first["tag"], second["tag"])

    def test_ciphertext_iv_and_tag_tampering_are_rejected(self) -> None:
        original = self.encrypt()
        changes = {
            "ciphertext": "00" + original["ciphertext"][2:],
            "iv": "ff" + original["iv"][2:],
            "tag": "ff" + original["tag"][2:],
        }
        for field, changed_value in changes.items():
            with self.subTest(field=field):
                tampered = dict(original)
                tampered[field] = changed_value
                with self.assertRaisesRegex(
                    authenticated_sm4.AuthenticationError, "authentication failed"
                ):
                    authenticated_sm4.verify_and_decrypt(
                        self.openssl, SM4_KEY, HMAC_KEY, tampered
                    )

    def test_wrong_hmac_key_is_rejected(self) -> None:
        with self.assertRaises(authenticated_sm4.AuthenticationError):
            authenticated_sm4.verify_and_decrypt(
                self.openssl, SM4_KEY, "ff" * 32, self.encrypt()
            )

    def test_authentication_failure_never_calls_decrypt(self) -> None:
        decrypt = Mock(side_effect=AssertionError("decrypt must not run"))
        value = self.encrypt()
        value["tag"] = "ff" * 32

        with self.assertRaises(authenticated_sm4.AuthenticationError):
            authenticated_sm4.verify_and_decrypt(
                self.openssl, SM4_KEY, HMAC_KEY, value, crypt_fn=decrypt
            )
        decrypt.assert_not_called()

    def test_version_and_algorithm_tampering_are_rejected(self) -> None:
        original = self.encrypt()
        for field, changed_value in (("version", 2), ("algorithm", "SM4-CTR")):
            with self.subTest(field=field):
                tampered = dict(original)
                tampered[field] = changed_value
                with self.assertRaises(authenticated_sm4.FormatError):
                    authenticated_sm4.verify_and_decrypt(
                        self.openssl, SM4_KEY, HMAC_KEY, tampered
                    )

    def test_wrong_sm4_key_does_not_replace_hmac_authentication(self) -> None:
        original = self.encrypt(b"secret")
        recovered = authenticated_sm4.verify_and_decrypt(
            self.openssl, "ff" * 16, HMAC_KEY, original
        )
        self.assertNotEqual(recovered, b"secret")

    def test_invalid_plaintext_and_iv_are_rejected(self) -> None:
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "plaintext"):
            authenticated_sm4.encrypt_and_authenticate(
                self.openssl, SM4_KEY, HMAC_KEY, "abc"  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(authenticated_sm4.FormatError, "16 bytes"):
            authenticated_sm4.encrypt_and_authenticate(
                self.openssl, SM4_KEY, HMAC_KEY, b"abc", iv=b"short"
            )


if __name__ == "__main__":
    unittest.main()
