"""Tests for the user-facing gmcrypto command-line interface."""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import gmcrypto
import runner


ABC_DIGEST = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
EMPTY_DIGEST = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
HMAC_KEY = "00112233445566778899aabbccddeeff"
ABC_HMAC = "0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d"
SM4_KEY = "0123456789abcdeffedcba9876543210"
AUTH_HMAC_KEY = "00112233445566778899aabbccddeeff" * 2


class TestGmcryptoSm3(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.openssl = shutil.which("openssl")
        if cls.openssl is None:
            raise unittest.SkipTest("OpenSSL is not available")

    def run_command(self, arguments: list[str]) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        result = gmcrypto.main(arguments, output=output, error_output=errors)
        return result, output.getvalue().strip(), errors.getvalue().strip()

    def test_text_abc(self) -> None:
        result, digest, errors = self.run_command(["sm3", "--text", "abc"])

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(digest, ABC_DIGEST)
        self.assertEqual(errors, "")

    def test_hex_abc(self) -> None:
        result, digest, _errors = self.run_command(["sm3", "--hex", "616263"])

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(digest, ABC_DIGEST)

    def test_empty_hex_message(self) -> None:
        result, digest, _errors = self.run_command(["sm3", "--hex", ""])

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(digest, EMPTY_DIGEST)

    def test_utf8_text(self) -> None:
        text = "国密算法"
        expected = runner.sm3_digest(self.openssl, text.encode("utf-8"))

        result, digest, _errors = self.run_command(["sm3", "--text", text])

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(digest, expected)

    def test_file_digest(self) -> None:
        content = b"SM3 file test\x00\xff"
        expected = runner.sm3_digest(self.openssl, content)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.bin"
            path.write_bytes(content)

            result, digest, _errors = self.run_command(
                ["sm3", "--file", str(path)]
            )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(digest, expected)

    def test_invalid_hex_returns_input_error(self) -> None:
        result, _digest, errors = self.run_command(["sm3", "--hex", "xyz"])

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("whole bytes", errors)

    def test_missing_file_returns_input_error(self) -> None:
        result, _digest, errors = self.run_command(
            ["sm3", "--file", "definitely-missing-message.bin"]
        )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("file not found", errors)


class TestGmcryptoHmacSm3(unittest.TestCase):
    def run_command(self, arguments: list[str]) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        result = gmcrypto.main(arguments, output=output, error_output=errors)
        return result, output.getvalue().strip(), errors.getvalue().strip()

    def test_text_tag(self) -> None:
        result, tag, errors = self.run_command(
            ["hmac-sm3", "--key-hex", HMAC_KEY, "--text", "abc"]
        )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(tag, ABC_HMAC)
        self.assertEqual(errors, "")

    def test_hex_tag(self) -> None:
        result, tag, _errors = self.run_command(
            ["hmac-sm3", "--key-hex", HMAC_KEY, "--hex", "616263"]
        )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(tag, ABC_HMAC)

    def test_file_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message.bin"
            path.write_bytes(b"abc")

            result, tag, _errors = self.run_command(
                ["hmac-sm3", "--key-hex", HMAC_KEY, "--file", str(path)]
            )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(tag, ABC_HMAC)

    def test_raw_key_file_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            key_path = Path(directory_name) / "test.hmackey"
            key_path.write_bytes(bytes.fromhex(HMAC_KEY))

            result, tag, errors = self.run_command(
                ["hmac-sm3", "--key-file", str(key_path), "--text", "abc"]
            )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(tag, ABC_HMAC)
        self.assertEqual(errors, "")

    def test_generate_hmac_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            key_path = Path(directory_name) / "generated.hmackey"

            result, reported, errors = self.run_command(
                ["generate-hmac-key", "--output", str(key_path)]
            )
            key = key_path.read_bytes()

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(reported, str(key_path))
        self.assertEqual(errors, "")
        self.assertEqual(len(key), 32)

    def test_empty_hmac_key_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            key_path = Path(directory_name) / "empty.hmackey"
            key_path.write_bytes(b"")

            result, _tag, errors = self.run_command(
                ["hmac-sm3", "--key-file", str(key_path), "--text", "abc"]
            )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("must not be empty", errors)

    def test_missing_hmac_key_file_is_rejected(self) -> None:
        result, _tag, errors = self.run_command(
            ["hmac-sm3", "--key-file", "missing.hmackey", "--text", "abc"]
        )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("not found", errors)

    def test_invalid_generated_hmac_key_length_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            result, _reported, errors = self.run_command(
                [
                    "generate-hmac-key",
                    "--output",
                    str(Path(directory_name) / "key.hmackey"),
                    "--bytes",
                    "0",
                ]
            )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("between 1 and 4096", errors)

    def test_verify_success(self) -> None:
        result, status, _errors = self.run_command(
            [
                "hmac-sm3",
                "--key-hex",
                HMAC_KEY,
                "--text",
                "abc",
                "--verify",
                ABC_HMAC.upper(),
            ]
        )

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(status, "OK")

    def test_verify_failure(self) -> None:
        result, status, _errors = self.run_command(
            [
                "hmac-sm3",
                "--key-hex",
                HMAC_KEY,
                "--text",
                "changed",
                "--verify",
                ABC_HMAC,
            ]
        )

        self.assertEqual(result, gmcrypto.EXIT_VERIFY_FAILURE)
        self.assertEqual(status, "FAIL")

    def test_invalid_key_hex(self) -> None:
        result, _tag, errors = self.run_command(
            ["hmac-sm3", "--key-hex", "zz", "--text", "abc"]
        )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("non-hexadecimal", errors)

    def test_empty_key_is_rejected(self) -> None:
        result, _tag, errors = self.run_command(
            ["hmac-sm3", "--key-hex", "", "--text", "abc"]
        )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("must not be empty", errors)

    def test_invalid_verify_tag_length(self) -> None:
        result, _status, errors = self.run_command(
            [
                "hmac-sm3",
                "--key-hex",
                HMAC_KEY,
                "--text",
                "abc",
                "--verify",
                "00",
            ]
        )

        self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
        self.assertIn("exactly 32 bytes", errors)


class TestGmcryptoAuthenticatedEncryption(unittest.TestCase):
    def run_command(self, arguments: list[str]) -> tuple[int, str, str]:
        output = io.StringIO()
        errors = io.StringIO()
        result = gmcrypto.main(arguments, output=output, error_output=errors)
        return result, output.getvalue().strip(), errors.getvalue().strip()

    def write_key_file(self, directory: Path) -> Path:
        path = directory / "auth-key.json"
        path.write_text(
            json.dumps({"sm4Key": SM4_KEY, "hmacKey": AUTH_HMAC_KEY}),
            encoding="utf-8",
        )
        return path

    def test_generate_key_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "generated-key.json"
            result, reported, errors = self.run_command(
                ["generate-auth-key", "--output", str(path)]
            )
            document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(result, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(reported, str(path))
        self.assertEqual(errors, "")
        self.assertEqual(len(document["sm4Key"]), 32)
        self.assertEqual(len(document["hmacKey"]), 64)

    def test_text_encrypt_and_file_decrypt_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            package = directory / "message.gmenc.json"
            plaintext = directory / "message.txt"

            encrypted, _, encrypt_errors = self.run_command(
                [
                    "encrypt-auth", "--key-file", str(key_file),
                    "--text", "国密实验", "--output", str(package),
                ]
            )
            decrypted, _, decrypt_errors = self.run_command(
                [
                    "decrypt-auth", "--key-file", str(key_file),
                    "--package", str(package), "--output", str(plaintext),
                ]
            )
            recovered = plaintext.read_text(encoding="utf-8")

        self.assertEqual(encrypted, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(decrypted, gmcrypto.EXIT_SUCCESS)
        self.assertEqual(encrypt_errors, "")
        self.assertEqual(decrypt_errors, "")
        self.assertEqual(recovered, "国密实验")

    def test_binary_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            source = directory / "source.bin"
            package = directory / "package.json"
            recovered = directory / "recovered.bin"
            content = b"binary\x00message\xff"
            source.write_bytes(content)

            encrypted, _, _ = self.run_command(
                ["encrypt-auth", "--key-file", str(key_file), "--file", str(source),
                 "--output", str(package)]
            )
            decrypted, _, _ = self.run_command(
                ["decrypt-auth", "--key-file", str(key_file), "--package", str(package),
                 "--output", str(recovered)]
            )

            self.assertEqual(encrypted, gmcrypto.EXIT_SUCCESS)
            self.assertEqual(decrypted, gmcrypto.EXIT_SUCCESS)
            self.assertEqual(recovered.read_bytes(), content)

    def test_tampered_package_creates_no_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            package_path = directory / "package.json"
            output_path = directory / "must-not-exist.bin"
            self.run_command(
                ["encrypt-auth", "--key-file", str(key_file), "--text", "secret",
                 "--output", str(package_path)]
            )
            package = json.loads(package_path.read_text(encoding="utf-8"))
            package["tag"] = "00" * 32
            package_path.write_text(json.dumps(package), encoding="utf-8")

            result, _, errors = self.run_command(
                ["decrypt-auth", "--key-file", str(key_file),
                 "--package", str(package_path), "--output", str(output_path)]
            )

            self.assertEqual(result, gmcrypto.EXIT_VERIFY_FAILURE)
            self.assertIn("authentication failed", errors)
            self.assertFalse(output_path.exists())

    def test_truncated_package_creates_no_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            package_path = directory / "truncated.json"
            output_path = directory / "must-not-exist.bin"
            package_path.write_text('{"version": 1,', encoding="utf-8")

            result, _, errors = self.run_command(
                [
                    "decrypt-auth", "--key-file", str(key_file),
                    "--package", str(package_path), "--output", str(output_path),
                ]
            )

            self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
            self.assertIn("valid UTF-8 JSON", errors)
            self.assertFalse(output_path.exists())

    def test_wrong_hmac_key_creates_no_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            wrong_key_file = directory / "wrong-auth-key.json"
            package_path = directory / "package.json"
            output_path = directory / "must-not-exist.bin"
            wrong_key_file.write_text(
                json.dumps({"sm4Key": SM4_KEY, "hmacKey": "ff" * 32}),
                encoding="utf-8",
            )
            self.run_command(
                [
                    "encrypt-auth", "--key-file", str(key_file), "--text", "secret",
                    "--output", str(package_path),
                ]
            )

            result, _, errors = self.run_command(
                [
                    "decrypt-auth", "--key-file", str(wrong_key_file),
                    "--package", str(package_path), "--output", str(output_path),
                ]
            )

            self.assertEqual(result, gmcrypto.EXIT_VERIFY_FAILURE)
            self.assertIn("authentication failed", errors)
            self.assertFalse(output_path.exists())

    def test_existing_output_is_not_replaced_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = self.write_key_file(directory)
            output_path = directory / "existing.json"
            output_path.write_bytes(b"keep")

            result, _, errors = self.run_command(
                ["encrypt-auth", "--key-file", str(key_file), "--hex", "00",
                 "--output", str(output_path)]
            )

            self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
            self.assertIn("already exists", errors)
            self.assertEqual(output_path.read_bytes(), b"keep")

    def test_invalid_key_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            key_file = directory / "bad-key.json"
            key_file.write_text(json.dumps({"sm4Key": "00"}), encoding="utf-8")

            result, _, errors = self.run_command(
                ["encrypt-auth", "--key-file", str(key_file), "--text", "x",
                 "--output", str(directory / "output.json")]
            )

            self.assertEqual(result, gmcrypto.EXIT_INPUT_ERROR)
            self.assertIn("exactly", errors)


if __name__ == "__main__":
    unittest.main()
