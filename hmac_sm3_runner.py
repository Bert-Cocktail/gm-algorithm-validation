#!/usr/bin/env python3
"""Validate HMAC-SM3 JSON test vectors with OpenSSL."""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any, TextIO


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
TAG_HEX_LENGTH = 64
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid HMAC-SM3 vectors or backend failures."""


def require_hex(
    value: Any,
    field: str,
    tc_id: Any,
    *,
    nonempty: bool = False,
    exact_length: int | None = None,
) -> str:
    if not isinstance(value, str):
        raise RunnerError(f"tcId={tc_id}: '{field}' must be a string")
    if len(value) % 2 != 0:
        raise RunnerError(f"tcId={tc_id}: '{field}' must contain whole bytes")
    if not HEX_RE.fullmatch(value):
        raise RunnerError(f"tcId={tc_id}: '{field}' contains non-hex characters")
    if nonempty and not value:
        raise RunnerError(f"tcId={tc_id}: '{field}' must not be empty")
    if exact_length is not None and len(value) != exact_length:
        raise RunnerError(
            f"tcId={tc_id}: '{field}' must contain {exact_length} hex characters"
        )
    return value.lower()


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
                    f"test group {group_index}, test {test_index}: 'tcId' must be an integer"
                )
            if tc_id in seen_ids:
                raise RunnerError(f"duplicate tcId: {tc_id}")
            seen_ids.add(tc_id)

            key = require_hex(test.get("key"), "key", tc_id, nonempty=True)
            message = require_hex(test.get("msg"), "msg", tc_id)
            tag = require_hex(
                test.get("tag"), "tag", tc_id, exact_length=TAG_HEX_LENGTH
            )
            msg_len = test.get("msgLen")
            if not isinstance(msg_len, int) or isinstance(msg_len, bool) or msg_len < 0:
                raise RunnerError(f"tcId={tc_id}: 'msgLen' must be a non-negative integer")
            if msg_len != len(message) * 4:
                raise RunnerError(
                    f"tcId={tc_id}: msgLen is {msg_len}, but msg contains "
                    f"{len(message) * 4} bits"
                )
            tests.append({"tcId": tc_id, "key": key, "msg": message, "tag": tag})

    if not tests:
        raise RunnerError("the vector file contains no tests")
    return tests


def hmac_sm3(openssl: str, key_hex: str, message: bytes) -> str:
    try:
        process = subprocess.run(
            [
                openssl, "dgst", "-sm3", "-mac", "HMAC",
                "-macopt", f"hexkey:{key_hex}", "-binary",
            ],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RunnerError(f"failed to start OpenSSL: {error}") from error

    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"OpenSSL HMAC-SM3 failed: {detail or 'unknown error'}")
    if len(process.stdout) != 32:
        raise RunnerError(
            f"OpenSSL returned {len(process.stdout)} bytes; "
            "an HMAC-SM3 tag must be 32 bytes"
        )
    return process.stdout.hex()


HmacFunction = Callable[[str, str, bytes], str]


def run_tests(
    tests: list[dict[str, Any]],
    openssl: str,
    *,
    hmac_fn: HmacFunction = hmac_sm3,
    output: TextIO = sys.stdout,
    results: list[dict[str, Any]] | None = None,
) -> int:
    passed = 0
    for test in tests:
        actual = hmac_fn(openssl, test["key"], bytes.fromhex(test["msg"]))
        matches = actual == test["tag"]
        if results is not None:
            results.append(
                {
                    "tcId": test["tcId"],
                    "status": "passed" if matches else "failed",
                    "expected": test["tag"],
                    "actual": actual,
                }
            )
        if matches:
            passed += 1
            print(f"[PASS] tcId={test['tcId']}", file=output)
        else:
            print(f"[FAIL] tcId={test['tcId']}", file=output)
            print(f"       expected: {test['tag']}", file=output)
            print(f"       actual:   {actual}", file=output)

    failed = len(tests) - passed
    print(f"\nTotal: {len(tests)}, Passed: {passed}, Failed: {failed}", file=output)
    return EXIT_SUCCESS if failed == 0 else EXIT_TEST_FAILURE
