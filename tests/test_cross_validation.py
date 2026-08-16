"""Cross-check all current vectors with the independent GmSSL backend."""

from __future__ import annotations

import inspect
import json
import shutil
import unittest
from pathlib import Path

import authenticated_sm4
import gmssl_backend
import hmac_sm3_runner
import runner
import sm4_runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SM4_STANDARD_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")
SM4_STANDARD_PT = bytes.fromhex("0123456789abcdeffedcba9876543210")
SM4_STANDARD_CT = "681edf34d206965e86b3e94f536e4246"


def load_vector(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "vectors" / name).read_text(encoding="utf-8"))


class TestGmsslCrossValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def test_sm4_standard_block_primitive(self) -> None:
        encrypted = gmssl_backend.gmssl_sm4_block(
            SM4_STANDARD_KEY, SM4_STANDARD_PT, "encrypt"
        )
        self.assertEqual(encrypted.hex(), SM4_STANDARD_CT)
        self.assertEqual(
            gmssl_backend.gmssl_sm4_block(
                SM4_STANDARD_KEY, encrypted, "decrypt"
            ),
            SM4_STANDARD_PT,
        )

    def test_all_sm3_vectors_match_both_backends(self) -> None:
        tests = runner.extract_tests(load_vector("sm3.json"))
        for test in tests:
            with self.subTest(tcId=test["tcId"]):
                message = bytes.fromhex(test["msg"])
                expected = test["md"]
                self.assertEqual(runner.sm3_digest(self.openssl, message), expected)
                self.assertEqual(gmssl_backend.gmssl_sm3(message), expected)

    def test_all_hmac_sm3_vectors_match_both_backends(self) -> None:
        tests = hmac_sm3_runner.extract_tests(load_vector("hmac-sm3.json"))
        for test in tests:
            with self.subTest(tcId=test["tcId"]):
                key = bytes.fromhex(test["key"])
                message = bytes.fromhex(test["msg"])
                expected = test["tag"]
                self.assertEqual(
                    hmac_sm3_runner.hmac_sm3(self.openssl, test["key"], message),
                    expected,
                )
                self.assertEqual(
                    gmssl_backend.gmssl_hmac_sm3(key, message), expected
                )

    def test_all_sm4_vectors_match_both_backends(self) -> None:
        tests = sm4_runner.extract_tests(load_vector("sm4.json"))
        for test in tests:
            with self.subTest(tcId=test["tcId"]):
                input_hex = test["pt"] if test["direction"] == "encrypt" else test["ct"]
                expected = test["ct"] if test["direction"] == "encrypt" else test["pt"]
                data = bytes.fromhex(input_hex)
                openssl_result = sm4_runner.sm4_crypt(
                    self.openssl,
                    test["mode"],
                    test["direction"],
                    test["key"],
                    test["iv"],
                    data,
                )
                gmssl_result = gmssl_backend.gmssl_sm4_crypt(
                    test["mode"],
                    test["direction"],
                    bytes.fromhex(test["key"]),
                    bytes.fromhex(test["iv"]) if test["iv"] is not None else None,
                    data,
                )
                self.assertEqual(openssl_result.hex(), expected)
                self.assertEqual(gmssl_result.hex(), expected)

    def test_authenticated_vector_matches_gmssl_backend(self) -> None:
        test = load_vector("sm4-ctr-hmac-sm3.json")["testGroups"][0]["tests"][0]
        sm4_key = bytes.fromhex(test["sm4Key"])
        hmac_key = bytes.fromhex(test["hmacKey"])
        iv = bytes.fromhex(test["iv"])
        plaintext = bytes.fromhex(test["pt"])
        ciphertext = gmssl_backend.gmssl_sm4_crypt(
            "CTR", "encrypt", sm4_key, iv, plaintext
        )
        authenticated_data = authenticated_sm4.build_authenticated_data(
            authenticated_sm4.VERSION,
            authenticated_sm4.ALGORITHM,
            iv,
            ciphertext,
        )
        tag = gmssl_backend.gmssl_hmac_sm3(hmac_key, authenticated_data)
        recovered = gmssl_backend.gmssl_sm4_crypt(
            "CTR", "decrypt", sm4_key, iv, ciphertext
        )
        self.assertEqual(ciphertext.hex(), test["ct"])
        self.assertEqual(tag, test["tag"])
        self.assertEqual(recovered, plaintext)

    def test_empty_authenticated_message_matches_both_backends(self) -> None:
        sm4_key_hex = "0123456789abcdeffedcba9876543210"
        hmac_key_hex = "00" * 32
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        package = authenticated_sm4.encrypt_and_authenticate(
            self.openssl, sm4_key_hex, hmac_key_hex, b"", iv=iv
        )
        ciphertext = gmssl_backend.gmssl_sm4_crypt(
            "CTR", "encrypt", bytes.fromhex(sm4_key_hex), iv, b""
        )
        authenticated_data = authenticated_sm4.build_authenticated_data(
            authenticated_sm4.VERSION,
            authenticated_sm4.ALGORITHM,
            iv,
            ciphertext,
        )
        self.assertEqual(package["ciphertext"], "")
        self.assertEqual(
            gmssl_backend.gmssl_hmac_sm3(
                bytes.fromhex(hmac_key_hex), authenticated_data
            ),
            package["tag"],
        )

    def test_backend_has_no_project_backend_dependency(self) -> None:
        source = inspect.getsource(gmssl_backend)
        forbidden = (
            "import subprocess",
            "import runner",
            "import sm4_runner",
            "import hmac_sm3_runner",
        )
        for text in forbidden:
            with self.subTest(text=text):
                self.assertNotIn(text, source)


if __name__ == "__main__":
    unittest.main()
