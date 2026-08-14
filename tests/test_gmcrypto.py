"""Tests for the user-facing gmcrypto command-line interface."""

from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from pathlib import Path

import gmcrypto
import runner


ABC_DIGEST = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
EMPTY_DIGEST = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"


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


if __name__ == "__main__":
    unittest.main()
