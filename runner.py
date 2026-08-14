#!/usr/bin/env python3
"""Run supported GM algorithm JSON test vectors with OpenSSL."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from io import TextIOBase
from pathlib import Path
from typing import Any

import sm4_runner
import hmac_sm3_runner


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
SM3_HEX_LENGTH = 64
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid input or an unavailable OpenSSL backend."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SM3, HMAC-SM3, or SM4 test vectors with OpenSSL."
    )
    parser.add_argument(
        "vector_file", type=Path, help="path to a supported JSON vector file"
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )
    return parser.parse_args(argv)


def load_document(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            document = json.load(file)
    except FileNotFoundError as error:
        raise RunnerError(f"vector file not found: {path}") from error
    except PermissionError as error:
        raise RunnerError(f"cannot read vector file: {path}") from error
    except json.JSONDecodeError as error:
        raise RunnerError(
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error

    if not isinstance(document, dict):
        raise RunnerError("the JSON root must be an object")
    return document


def load_vectors(path: Path) -> dict[str, Any]:
    """Load an SM3 vector file; retained for direct SM3 use and tests."""
    document = load_document(path)
    if str(document.get("algorithm", "")).upper() != "SM3":
        raise RunnerError("the 'algorithm' field must be 'SM3'")
    if not isinstance(document.get("testGroups"), list):
        raise RunnerError("the 'testGroups' field must be an array")
    return document


def require_hex(value: Any, field: str, tc_id: Any, expected_length: int | None = None) -> str:
    if not isinstance(value, str):
        raise RunnerError(f"tcId={tc_id}: '{field}' must be a string")
    if len(value) % 2 != 0:
        raise RunnerError(f"tcId={tc_id}: '{field}' must contain whole bytes")
    if not HEX_RE.fullmatch(value):
        raise RunnerError(f"tcId={tc_id}: '{field}' contains non-hex characters")
    if expected_length is not None and len(value) != expected_length:
        raise RunnerError(
            f"tcId={tc_id}: '{field}' must contain {expected_length} hex characters"
        )
    return value.lower()


def extract_tests(document: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    seen_ids: set[Any] = set()

    for group_index, group in enumerate(document["testGroups"], start=1):
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

            msg = require_hex(test.get("msg"), "msg", tc_id)
            expected = require_hex(
                test.get("md"), "md", tc_id, expected_length=SM3_HEX_LENGTH
            )
            msg_len = test.get("msgLen")
            if not isinstance(msg_len, int) or isinstance(msg_len, bool) or msg_len < 0:
                raise RunnerError(f"tcId={tc_id}: 'msgLen' must be a non-negative integer")
            if msg_len != len(msg) * 4:
                raise RunnerError(
                    f"tcId={tc_id}: msgLen is {msg_len}, but msg contains {len(msg) * 4} bits"
                )

            tests.append({"tcId": tc_id, "msg": msg, "md": expected})

    if not tests:
        raise RunnerError("the vector file contains no tests")
    return tests


def resolve_openssl(command: str) -> str:
    candidate = Path(command)
    if candidate.parent != Path("."):
        if not candidate.is_file():
            raise RunnerError(f"OpenSSL executable not found: {command}")
        return str(candidate)

    resolved = shutil.which(command)
    if resolved is None:
        raise RunnerError(
            "OpenSSL was not found. Add it to PATH or use --openssl <path>."
        )
    return resolved


def sm3_digest(openssl: str, message: bytes) -> str:
    try:
        process = subprocess.run(
            [openssl, "dgst", "-sm3", "-binary"],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RunnerError(f"failed to start OpenSSL: {error}") from error

    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"OpenSSL SM3 failed: {detail or 'unknown error'}")
    if len(process.stdout) != 32:
        raise RunnerError(
            f"OpenSSL returned {len(process.stdout)} bytes; an SM3 digest must be 32 bytes"
        )
    return process.stdout.hex()


def run_tests(
    tests: list[dict[str, Any]],
    openssl: str,
    *,
    digest_fn: Callable[[str, bytes], str] = sm3_digest,
    output: TextIOBase = sys.stdout,
) -> int:
    passed = 0

    for test in tests:
        tc_id = test["tcId"]
        actual = digest_fn(openssl, bytes.fromhex(test["msg"]))
        expected = test["md"]

        if actual == expected:
            passed += 1
            print(f"[PASS] tcId={tc_id}", file=output)
        else:
            print(f"[FAIL] tcId={tc_id}", file=output)
            print(f"       expected: {expected}", file=output)
            print(f"       actual:   {actual}", file=output)

    failed = len(tests) - passed
    print(
        f"\nTotal: {len(tests)}, Passed: {passed}, Failed: {failed}",
        file=output,
    )
    return EXIT_SUCCESS if failed == 0 else EXIT_TEST_FAILURE


def run_document(document: dict[str, Any], openssl: str) -> int:
    algorithm = str(document.get("algorithm", "")).upper()

    if algorithm == "SM3":
        if not isinstance(document.get("testGroups"), list):
            raise RunnerError("the 'testGroups' field must be an array")
        return run_tests(extract_tests(document), openssl)

    if algorithm == "SM4":
        if not isinstance(document.get("testGroups"), list):
            raise RunnerError("the 'testGroups' field must be an array")
        return sm4_runner.run_tests(sm4_runner.extract_tests(document), openssl)

    if algorithm == "HMAC-SM3":
        return hmac_sm3_runner.run_tests(
            hmac_sm3_runner.extract_tests(document), openssl
        )

    name = algorithm or "<missing>"
    raise RunnerError(
        f"unsupported algorithm '{name}'; supported algorithms: SM3, HMAC-SM3, SM4"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        document = load_document(args.vector_file)
        openssl = resolve_openssl(args.openssl)
        return run_document(document, openssl)
    except (RunnerError, hmac_sm3_runner.RunnerError, sm4_runner.RunnerError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
