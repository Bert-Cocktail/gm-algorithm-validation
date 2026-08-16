"""Tests for the local ACVP-style request/response adapter."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import acvp_adapter


VERSION = {"acvVersion": "1.0"}
SM4_KEY = "0123456789abcdeffedcba9876543210"
IV = "000102030405060708090a0b0c0d0e0f"


class TestAcvpAdapter(unittest.TestCase):
    def run_request(
        self, request: dict, *extra_arguments: str
    ) -> tuple[int, list[dict]]:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            request_path = directory / "request.json"
            response_path = directory / "response.json"
            request_path.write_text(
                json.dumps([VERSION, request]), encoding="utf-8"
            )
            with redirect_stderr(io.StringIO()):
                exit_code = acvp_adapter.main(
                    [
                        str(request_path),
                        "--output",
                        str(response_path),
                        *extra_arguments,
                    ]
                )
            response = (
                json.loads(response_path.read_text(encoding="utf-8"))
                if response_path.exists()
                else []
            )
        return exit_code, response

    def test_sm3_request_produces_message_digest(self) -> None:
        request = {
            "vsId": 1,
            "algorithm": "SM3",
            "testGroups": [
                {"tgId": 1, "tests": [{"tcId": 1, "msg": "616263", "msgLen": 24}]}
            ],
        }

        exit_code, response = self.run_request(request)

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertEqual(response[0], VERSION)
        self.assertEqual(
            response[1]["testGroups"][0]["tests"][0]["md"],
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        )

    def test_hmac_request_produces_mac(self) -> None:
        request = {
            "vsId": 2,
            "algorithm": "HMAC-SM3",
            "testGroups": [
                {
                    "tgId": 1,
                    "tests": [
                        {
                            "tcId": 1,
                            "key": "00112233445566778899aabbccddeeff",
                            "msg": "616263",
                            "msgLen": 24,
                        }
                    ],
                }
            ],
        }

        exit_code, response = self.run_request(request)

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertEqual(
            response[1]["testGroups"][0]["tests"][0]["mac"],
            "0933617a88d312f6f9fb4b5f200e31a64d655e92f7fa2a43f55dfeeb8ab6788d",
        )

    def test_sm4_encrypt_and_decrypt_groups(self) -> None:
        request = {
            "vsId": 3,
            "algorithm": "SM4",
            "testGroups": [
                {
                    "tgId": 1,
                    "mode": "ECB",
                    "direction": "encrypt",
                    "tests": [{"tcId": 1, "key": SM4_KEY, "pt": SM4_KEY}],
                },
                {
                    "tgId": 2,
                    "mode": "ECB",
                    "direction": "decrypt",
                    "tests": [
                        {
                            "tcId": 2,
                            "key": SM4_KEY,
                            "ct": "681edf34d206965e86b3e94f536e4246",
                        }
                    ],
                },
            ],
        }

        exit_code, response = self.run_request(request)
        groups = response[1]["testGroups"]

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertEqual(groups[0]["tests"][0]["ct"], "681edf34d206965e86b3e94f536e4246")
        self.assertEqual(groups[1]["tests"][0]["pt"], SM4_KEY)

    def test_authenticated_experiment_produces_ciphertext_and_tag(self) -> None:
        request = {
            "vsId": 4,
            "algorithm": "SM4-CTR-HMAC-SM3",
            "testGroups": [
                {
                    "tgId": 1,
                    "tests": [
                        {
                            "tcId": 1,
                            "sm4Key": SM4_KEY,
                            "hmacKey": "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
                            "iv": IV,
                            "pt": "616263",
                        }
                    ],
                }
            ],
        }

        exit_code, response = self.run_request(request)
        result = response[1]["testGroups"][0]["tests"][0]

        self.assertEqual(exit_code, acvp_adapter.EXIT_SUCCESS)
        self.assertEqual(result["ct"], "67faff")
        self.assertEqual(
            result["tag"],
            "3c08e5f08855380ee0fbabd47aed4dbae5db19ebbe7b001a42fa8c69aaf97ade",
        )

    def test_duplicate_id_and_request_overwrite_are_rejected(self) -> None:
        duplicate_request = {
            "vsId": 5,
            "algorithm": "SM3",
            "testGroups": [
                {"tgId": 1, "tests": [{"tcId": 1, "msg": "", "msgLen": 0}]},
                {"tgId": 1, "tests": [{"tcId": 2, "msg": "", "msgLen": 0}]},
            ],
        }
        exit_code, response = self.run_request(duplicate_request)
        self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
        self.assertEqual(response, [])

        with tempfile.TemporaryDirectory() as directory_name:
            request_path = Path(directory_name) / "request.json"
            request_path.write_text(
                json.dumps([VERSION, duplicate_request]), encoding="utf-8"
            )
            original = request_path.read_bytes()
            with redirect_stderr(io.StringIO()):
                exit_code = acvp_adapter.main(
                    [str(request_path), "--output", str(request_path)]
                )
            self.assertEqual(exit_code, acvp_adapter.EXIT_INPUT_ERROR)
            self.assertEqual(request_path.read_bytes(), original)

    def test_cross_backend_collects_all_mismatches_in_diagnostics(self) -> None:
        tests = [
            {"tcId": 1, "msg": "", "msgLen": 0},
            {"tcId": 2, "msg": "616263", "msgLen": 24},
        ]
        request = {
            "vsId": 6,
            "algorithm": "SM3",
            "testGroups": [{"tgId": 1, "tests": tests}],
        }

        with patch("gmssl_backend.gmssl_sm3", return_value="00" * 32):
            exit_code, response = self.run_request(request, "--backend", "cross")

        diagnostics = response[1]["localDiagnostics"]
        self.assertEqual(exit_code, acvp_adapter.EXIT_TEST_FAILURE)
        self.assertEqual(diagnostics["backend"], "cross")
        self.assertEqual(len(diagnostics["mismatches"]), 2)
        self.assertEqual(
            [item["tcId"] for item in diagnostics["mismatches"]], [1, 2]
        )
        self.assertEqual(len(response[1]["testGroups"][0]["tests"]), 2)


if __name__ == "__main__":
    unittest.main()
