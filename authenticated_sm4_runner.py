#!/usr/bin/env python3
"""Validate authenticated SM4-CTR + HMAC-SM3 experiment vectors."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any, TextIO

import authenticated_sm4


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1


class RunnerError(Exception):
    """Raised when an authenticated SM4 vector document is invalid."""


def _hex(
    value: Any,
    field: str,
    tc_id: int,
    *,
    exact_bytes: int | None = None,
) -> str:
    try:
        return authenticated_sm4.normalize_hex(
            value, field, exact_bytes=exact_bytes
        )
    except authenticated_sm4.FormatError as error:
        raise RunnerError(f"tcId={tc_id}: {error}") from error


def extract_tests(document: dict[str, Any]) -> list[dict[str, Any]]:
    groups = document.get("testGroups")
    if not isinstance(groups, list):
        raise RunnerError("the 'testGroups' field must be an array")

    tests: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for group_index, group in enumerate(groups, start=1):
        if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
            raise RunnerError(f"test group {group_index}: 'tests' must be an array")
        for test_index, test in enumerate(group["tests"], start=1):
            if not isinstance(test, dict):
                raise RunnerError(
                    f"test group {group_index}, test {test_index} must be an object"
                )
            tc_id = test.get("tcId")
            if not isinstance(tc_id, int) or isinstance(tc_id, bool):
                raise RunnerError(
                    f"test group {group_index}, test {test_index}: "
                    "'tcId' must be an integer"
                )
            if tc_id in seen_ids:
                raise RunnerError(f"duplicate tcId: {tc_id}")
            seen_ids.add(tc_id)

            try:
                sm4_key, hmac_key = authenticated_sm4.validate_keys(
                    test.get("sm4Key"), test.get("hmacKey")
                )
            except authenticated_sm4.FormatError as error:
                raise RunnerError(f"tcId={tc_id}: {error}") from error

            iv = _hex(
                test.get("iv"), "iv", tc_id, exact_bytes=authenticated_sm4.IV_BYTES
            )
            plaintext = _hex(test.get("pt"), "pt", tc_id)
            ciphertext = _hex(test.get("ct"), "ct", tc_id)
            tag = _hex(
                test.get("tag"),
                "tag",
                tc_id,
                exact_bytes=authenticated_sm4.TAG_BYTES,
            )
            if len(plaintext) != len(ciphertext):
                raise RunnerError(
                    f"tcId={tc_id}: 'pt' and 'ct' must have the same length"
                )
            tests.append(
                {
                    "tcId": tc_id,
                    "sm4Key": sm4_key,
                    "hmacKey": hmac_key,
                    "iv": iv,
                    "pt": plaintext,
                    "ct": ciphertext,
                    "tag": tag,
                }
            )

    if not tests:
        raise RunnerError("the vector file contains no tests")
    return tests


EncryptFunction = Callable[..., authenticated_sm4.AuthenticatedPackage]
DecryptFunction = Callable[..., bytes]


def run_tests(
    tests: list[dict[str, Any]],
    openssl: str,
    *,
    encrypt_fn: EncryptFunction = authenticated_sm4.encrypt_and_authenticate,
    decrypt_fn: DecryptFunction = authenticated_sm4.verify_and_decrypt,
    output: TextIO = sys.stdout,
) -> int:
    passed = 0
    for test in tests:
        actual_package = encrypt_fn(
            openssl,
            test["sm4Key"],
            test["hmacKey"],
            bytes.fromhex(test["pt"]),
            iv=bytes.fromhex(test["iv"]),
        )
        recovered = decrypt_fn(
            openssl, test["sm4Key"], test["hmacKey"], actual_package
        )
        actual_pt = recovered.hex()
        matches = (
            actual_package["ciphertext"] == test["ct"]
            and actual_package["tag"] == test["tag"]
            and actual_pt == test["pt"]
        )
        if matches:
            passed += 1
            print(f"[PASS] tcId={test['tcId']} algorithm={authenticated_sm4.ALGORITHM}", file=output)
        else:
            print(f"[FAIL] tcId={test['tcId']} algorithm={authenticated_sm4.ALGORITHM}", file=output)
            print(f"       expected ct:  {test['ct']}", file=output)
            print(f"       actual ct:    {actual_package['ciphertext']}", file=output)
            print(f"       expected tag: {test['tag']}", file=output)
            print(f"       actual tag:   {actual_package['tag']}", file=output)
            print(f"       recovered pt: {actual_pt}", file=output)

    failed = len(tests) - passed
    print(f"\nTotal: {len(tests)}, Passed: {passed}, Failed: {failed}", file=output)
    return EXIT_SUCCESS if failed == 0 else EXIT_TEST_FAILURE
