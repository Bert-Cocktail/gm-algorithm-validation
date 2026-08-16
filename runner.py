#!/usr/bin/env python3
"""Run supported GM algorithm vectors with selectable crypto backends."""

from __future__ import annotations

import argparse
import importlib
import json
import re
import shutil
import subprocess
import sys
import os
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from io import TextIOBase
from pathlib import Path
from typing import Any

import sm4_runner
import hmac_sm3_runner
import authenticated_sm4
import authenticated_sm4_runner


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
SM3_HEX_LENGTH = 64
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid input or an unavailable crypto backend."""


class CrossBackendMismatch(Exception):
    """Raised when OpenSSL and GmSSL return different results."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run SM3, HMAC-SM3, SM4, or authenticated SM4 test vectors "
            "with OpenSSL, GmSSL, or both."
        )
    )
    parser.add_argument(
        "vector_file", type=Path, help="path to a supported JSON vector file"
    )
    parser.add_argument(
        "--backend",
        choices=("openssl", "gmssl", "cross"),
        default="openssl",
        help="crypto backend (default: openssl)",
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )
    parser.add_argument(
        "--result-json",
        type=Path,
        help="write a structured JSON test report to this path",
    )
    return parser.parse_args(argv)


def _load_gmssl_backend() -> Any:
    try:
        return importlib.import_module("gmssl_backend")
    except ImportError as error:
        raise RunnerError(
            "the GmSSL backend is unavailable. Activate the project virtual "
            "environment and run: python -m pip install -r requirements-dev.txt"
        ) from error


def _compare_backend_results(operation: str, openssl_result: Any, gmssl_result: Any) -> Any:
    if openssl_result != gmssl_result:
        def display(value: Any) -> str:
            return value.hex() if isinstance(value, bytes) else str(value)

        raise CrossBackendMismatch(
            f"{operation}: OpenSSL={display(openssl_result)}, "
            f"GmSSL={display(gmssl_result)}"
        )
    return openssl_result


def _digest_function(backend: str) -> Callable[[str, bytes], str]:
    if backend == "openssl":
        return sm3_digest

    gmssl = _load_gmssl_backend()

    def gmssl_digest(_command: str, message: bytes) -> str:
        return gmssl.gmssl_sm3(message)

    if backend == "gmssl":
        return gmssl_digest

    def cross_digest(command: str, message: bytes) -> str:
        return _compare_backend_results(
            "SM3",
            sm3_digest(command, message),
            gmssl_digest(command, message),
        )

    return cross_digest


def _hmac_function(backend: str) -> Callable[[str, str, bytes], str]:
    if backend == "openssl":
        return hmac_sm3_runner.hmac_sm3

    gmssl = _load_gmssl_backend()

    def gmssl_hmac(_command: str, key_hex: str, message: bytes) -> str:
        return gmssl.gmssl_hmac_sm3(bytes.fromhex(key_hex), message)

    if backend == "gmssl":
        return gmssl_hmac

    def cross_hmac(command: str, key_hex: str, message: bytes) -> str:
        return _compare_backend_results(
            "HMAC-SM3",
            hmac_sm3_runner.hmac_sm3(command, key_hex, message),
            gmssl_hmac(command, key_hex, message),
        )

    return cross_hmac


def _crypt_function(
    backend: str,
) -> Callable[[str, str, str, str, Any, bytes], bytes]:
    if backend == "openssl":
        return sm4_runner.sm4_crypt

    gmssl = _load_gmssl_backend()

    def gmssl_crypt(
        _command: str,
        mode: str,
        direction: str,
        key_hex: str,
        iv_hex: Any,
        data: bytes,
    ) -> bytes:
        return gmssl.gmssl_sm4_crypt(
            mode,
            direction,
            bytes.fromhex(key_hex),
            bytes.fromhex(iv_hex) if iv_hex is not None else None,
            data,
        )

    if backend == "gmssl":
        return gmssl_crypt

    def cross_crypt(
        command: str,
        mode: str,
        direction: str,
        key_hex: str,
        iv_hex: Any,
        data: bytes,
    ) -> bytes:
        return _compare_backend_results(
            f"SM4-{mode} {direction}",
            sm4_runner.sm4_crypt(
                command, mode, direction, key_hex, iv_hex, data
            ),
            gmssl_crypt(command, mode, direction, key_hex, iv_hex, data),
        )

    return cross_crypt


def _authenticated_functions(backend: str) -> tuple[Callable[..., Any], Callable[..., bytes]]:
    crypt_fn = _crypt_function(backend)
    hmac_fn = _hmac_function(backend)

    def encrypt(
        command: str,
        sm4_key_hex: str,
        hmac_key_hex: str,
        plaintext: bytes,
        *,
        iv: bytes | None = None,
    ) -> authenticated_sm4.AuthenticatedPackage:
        return authenticated_sm4.encrypt_and_authenticate(
            command,
            sm4_key_hex,
            hmac_key_hex,
            plaintext,
            iv=iv,
            crypt_fn=crypt_fn,
            hmac_fn=hmac_fn,
        )

    def decrypt(
        command: str,
        sm4_key_hex: str,
        hmac_key_hex: str,
        package: Any,
    ) -> bytes:
        return authenticated_sm4.verify_and_decrypt(
            command,
            sm4_key_hex,
            hmac_key_hex,
            package,
            crypt_fn=crypt_fn,
            hmac_fn=hmac_fn,
        )

    return encrypt, decrypt


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
    results: list[dict[str, Any]] | None = None,
) -> int:
    passed = 0

    for test in tests:
        tc_id = test["tcId"]
        actual = digest_fn(openssl, bytes.fromhex(test["msg"]))
        expected = test["md"]

        matches = actual == expected
        if results is not None:
            results.append(
                {
                    "tcId": tc_id,
                    "status": "passed" if matches else "failed",
                    "expected": expected,
                    "actual": actual,
                }
            )

        if matches:
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


def run_document(
    document: dict[str, Any],
    openssl: str,
    *,
    backend: str = "openssl",
    results: list[dict[str, Any]] | None = None,
) -> int:
    algorithm = str(document.get("algorithm", "")).upper()

    if algorithm == "SM3":
        if not isinstance(document.get("testGroups"), list):
            raise RunnerError("the 'testGroups' field must be an array")
        return run_tests(
            extract_tests(document),
            openssl,
            digest_fn=_digest_function(backend),
            results=results,
        )

    if algorithm == "SM4":
        if not isinstance(document.get("testGroups"), list):
            raise RunnerError("the 'testGroups' field must be an array")
        return sm4_runner.run_tests(
            sm4_runner.extract_tests(document),
            openssl,
            crypt_fn=_crypt_function(backend),
            results=results,
        )

    if algorithm == "HMAC-SM3":
        return hmac_sm3_runner.run_tests(
            hmac_sm3_runner.extract_tests(document),
            openssl,
            hmac_fn=_hmac_function(backend),
            results=results,
        )

    if algorithm == "SM4-CTR-HMAC-SM3":
        encrypt_fn, decrypt_fn = _authenticated_functions(backend)
        return authenticated_sm4_runner.run_tests(
            authenticated_sm4_runner.extract_tests(document),
            openssl,
            encrypt_fn=encrypt_fn,
            decrypt_fn=decrypt_fn,
            results=results,
        )

    name = algorithm or "<missing>"
    raise RunnerError(
        f"unsupported algorithm '{name}'; supported algorithms: "
        "SM3, HMAC-SM3, SM4, SM4-CTR-HMAC-SM3"
    )


def _write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    if not path.parent.exists() or not path.parent.is_dir():
        raise RunnerError(f"result directory not found: {path.parent}")
    encoded = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as result_file:
            result_file.write(encoded)
            result_file.flush()
            os.fsync(result_file.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as error:
        raise RunnerError(f"failed to write result JSON: {error}") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def _build_report(
    args: argparse.Namespace,
    algorithm: str | None,
    tests: list[dict[str, Any]],
    exit_code: int,
    error: dict[str, str] | None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "vectorFile": str(args.vector_file.resolve()),
        "algorithm": algorithm,
        "backend": args.backend,
        "status": (
            "passed" if exit_code == EXIT_SUCCESS
            else "failed" if exit_code == EXIT_TEST_FAILURE
            else "error"
        ),
        "exitCode": exit_code,
        "summary": None,
        "tests": tests,
    }
    if exit_code in (EXIT_SUCCESS, EXIT_TEST_FAILURE) and error is None:
        passed = sum(test["status"] == "passed" for test in tests)
        report["summary"] = {
            "total": len(tests),
            "passed": passed,
            "failed": len(tests) - passed,
        }
    if error is not None:
        report["error"] = error
    return report


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    test_results: list[dict[str, Any]] = []
    algorithm: str | None = None
    error_detail: dict[str, str] | None = None
    result_path_is_vector = (
        args.result_json is not None
        and args.result_json.resolve() == args.vector_file.resolve()
    )
    try:
        if result_path_is_vector:
            raise RunnerError("result JSON path must not overwrite the vector file")
        document = load_document(args.vector_file)
        raw_algorithm = document.get("algorithm")
        algorithm = str(raw_algorithm).upper() if raw_algorithm is not None else None
        openssl = resolve_openssl(args.openssl) if args.backend != "gmssl" else ""
        exit_code = run_document(
            document, openssl, backend=args.backend, results=test_results
        )
    except CrossBackendMismatch as error:
        print(f"[FAIL] backend mismatch: {error}", file=sys.stderr)
        exit_code = EXIT_TEST_FAILURE
        error_detail = {"type": "backend_mismatch", "message": str(error)}
    except (
        RunnerError,
        authenticated_sm4.FormatError,
        authenticated_sm4.AuthenticationError,
        authenticated_sm4_runner.RunnerError,
        hmac_sm3_runner.RunnerError,
        sm4_runner.RunnerError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        exit_code = EXIT_INPUT_ERROR
        error_detail = {"type": "input_error", "message": str(error)}

    if args.result_json is not None and not result_path_is_vector:
        report = _build_report(
            args, algorithm, test_results, exit_code, error_detail
        )
        try:
            _write_json_atomic(args.result_json, report)
        except RunnerError as error:
            print(f"Error: {error}", file=sys.stderr)
            return EXIT_INPUT_ERROR
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
