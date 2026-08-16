#!/usr/bin/env python3
"""Run SM4 ECB/CBC/CTR JSON test vectors with OpenSSL."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Optional, TextIO


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
SM4_BLOCK_HEX_LENGTH = 32
SM4_KEY_HEX_LENGTH = 32
SUPPORTED_MODES = {"ECB", "CBC", "CTR"}
SUPPORTED_DIRECTIONS = {"encrypt", "decrypt"}
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid vectors or an unavailable OpenSSL backend."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SM4 ECB/CBC/CTR test vectors with OpenSSL."
    )
    parser.add_argument("vector_file", type=Path, help="path to an SM4 JSON file")
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )
    return parser.parse_args(argv)


def load_vectors(path: Path) -> dict[str, Any]:
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
    if str(document.get("algorithm", "")).upper() != "SM4":
        raise RunnerError("the 'algorithm' field must be 'SM4'")
    if not isinstance(document.get("testGroups"), list):
        raise RunnerError("the 'testGroups' field must be an array")
    return document


def require_hex(
    value: Any,
    field: str,
    tc_id: Any,
    *,
    exact_length: int | None = None,
    block_aligned: bool = False,
) -> str:
    if not isinstance(value, str):
        raise RunnerError(f"tcId={tc_id}: '{field}' must be a string")
    if len(value) % 2 != 0:
        raise RunnerError(f"tcId={tc_id}: '{field}' must contain whole bytes")
    if not HEX_RE.fullmatch(value):
        raise RunnerError(f"tcId={tc_id}: '{field}' contains non-hex characters")
    if exact_length is not None and len(value) != exact_length:
        raise RunnerError(
            f"tcId={tc_id}: '{field}' must contain {exact_length} hex characters"
        )
    if block_aligned and (not value or len(value) % SM4_BLOCK_HEX_LENGTH != 0):
        raise RunnerError(
            f"tcId={tc_id}: '{field}' must contain a non-empty whole number of "
            "16-byte SM4 blocks when padding is disabled"
        )
    return value.lower()


def extract_tests(document: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    seen_ids: set[int] = set()

    for group_index, group in enumerate(document["testGroups"], start=1):
        if not isinstance(group, dict):
            raise RunnerError(f"test group {group_index} must be an object")

        mode = str(group.get("mode", "")).upper()
        if mode not in SUPPORTED_MODES:
            supported = ", ".join(sorted(SUPPORTED_MODES))
            raise RunnerError(
                f"test group {group_index}: unsupported mode '{mode}'; "
                f"supported modes: {supported}"
            )

        direction = str(group.get("direction", "")).lower()
        if direction not in SUPPORTED_DIRECTIONS:
            raise RunnerError(
                f"test group {group_index}: direction must be 'encrypt' or 'decrypt'"
            )

        group_tests = group.get("tests")
        if not isinstance(group_tests, list):
            raise RunnerError(f"test group {group_index}: 'tests' must be an array")

        for test_index, test in enumerate(group_tests, start=1):
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

            key = require_hex(
                test.get("key"), "key", tc_id, exact_length=SM4_KEY_HEX_LENGTH
            )
            block_aligned = mode in {"ECB", "CBC"}
            plaintext = require_hex(
                test.get("pt"), "pt", tc_id, block_aligned=block_aligned
            )
            ciphertext = require_hex(
                test.get("ct"), "ct", tc_id, block_aligned=block_aligned
            )
            if mode == "CTR" and (not plaintext or not ciphertext):
                raise RunnerError(
                    f"tcId={tc_id}: 'pt' and 'ct' must not be empty"
                )
            if len(plaintext) != len(ciphertext):
                raise RunnerError(
                    f"tcId={tc_id}: 'pt' and 'ct' must have the same length"
                )

            iv: str | None = None
            if mode in {"CBC", "CTR"}:
                iv = require_hex(
                    test.get("iv"), "iv", tc_id, exact_length=SM4_BLOCK_HEX_LENGTH
                )
            elif "iv" in test:
                raise RunnerError(f"tcId={tc_id}: ECB mode must not include an IV")

            tests.append(
                {
                    "tcId": tc_id,
                    "mode": mode,
                    "direction": direction,
                    "key": key,
                    "iv": iv,
                    "pt": plaintext,
                    "ct": ciphertext,
                }
            )

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


def sm4_crypt(
    openssl: str,
    mode: str,
    direction: str,
    key: str,
    iv: str | None,
    data: bytes,
) -> bytes:
    command = [openssl, "enc", f"-sm4-{mode.lower()}", "-K", key, "-nopad"]
    if direction == "decrypt":
        command.append("-d")
    if mode in {"CBC", "CTR"}:
        if iv is None:
            raise RunnerError(f"{mode} mode requires an IV")
        command.extend(["-iv", iv])

    try:
        process = subprocess.run(
            command,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise RunnerError(f"failed to start OpenSSL: {error}") from error

    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"OpenSSL SM4 failed: {detail or 'unknown error'}")
    if len(process.stdout) != len(data):
        raise RunnerError(
            f"OpenSSL returned {len(process.stdout)} bytes for {len(data)} input bytes"
        )
    return process.stdout


CryptFunction = Callable[[str, str, str, str, Optional[str], bytes], bytes]


def run_tests(
    tests: list[dict[str, Any]],
    openssl: str,
    *,
    crypt_fn: CryptFunction = sm4_crypt,
    output: TextIO = sys.stdout,
    results: list[dict[str, Any]] | None = None,
) -> int:
    passed = 0

    for test in tests:
        direction = test["direction"]
        input_hex = test["pt"] if direction == "encrypt" else test["ct"]
        expected = test["ct"] if direction == "encrypt" else test["pt"]
        try:
            actual = crypt_fn(
                openssl,
                test["mode"],
                direction,
                test["key"],
                test["iv"],
                bytes.fromhex(input_hex),
            ).hex()
        except Exception as error:
            if hasattr(error, "set_test_context"):
                error.set_test_context(
                    test["tcId"], mode=test["mode"], direction=direction
                )
            raise

        label = (
            f"tcId={test['tcId']} mode={test['mode']} "
            f"direction={direction}"
        )
        matches = actual == expected
        if results is not None:
            results.append(
                {
                    "tcId": test["tcId"],
                    "mode": test["mode"],
                    "direction": direction,
                    "status": "passed" if matches else "failed",
                    "expected": expected,
                    "actual": actual,
                }
            )
        if matches:
            passed += 1
            print(f"[PASS] {label}", file=output)
        else:
            print(f"[FAIL] {label}", file=output)
            print(f"       expected: {expected}", file=output)
            print(f"       actual:   {actual}", file=output)

    failed = len(tests) - passed
    print(
        f"\nTotal: {len(tests)}, Passed: {passed}, Failed: {failed}",
        file=output,
    )
    return EXIT_SUCCESS if failed == 0 else EXIT_TEST_FAILURE


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        document = load_vectors(args.vector_file)
        tests = extract_tests(document)
        openssl = resolve_openssl(args.openssl)
        return run_tests(tests, openssl)
    except RunnerError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
