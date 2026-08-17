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
import sm2_runner
import sm2_encryption_runner
import sm2_cipher


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
SM3_HEX_LENGTH = 64
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid input or an unavailable crypto backend."""


class CrossBackendMismatch(Exception):
    """Raised when OpenSSL and GmSSL return different results."""

    def __init__(self, operation: str, openssl_result: Any, gmssl_result: Any):
        self._openssl_raw = openssl_result
        self._gmssl_raw = gmssl_result
        self.operation = operation
        self.openssl_result = self._display(openssl_result)
        self.gmssl_result = self._display(gmssl_result)
        self.tc_id: int | None = None
        self.context: dict[str, Any] = {}
        super().__init__(operation)

    @property
    def preferred_result(self) -> Any:
        """Return the OpenSSL result so validation can continue after recording."""
        return self._openssl_raw

    @staticmethod
    def _display(value: Any) -> str:
        return value.hex() if isinstance(value, bytes) else str(value)

    def set_test_context(self, tc_id: int, **context: Any) -> None:
        self.tc_id = tc_id
        self.context = context

    def as_error_detail(self) -> dict[str, Any]:
        detail: dict[str, Any] = {
            "type": "backend_mismatch",
            "message": str(self),
            "operation": self.operation,
            "openssl": self.openssl_result,
            "gmssl": self.gmssl_result,
        }
        if self.tc_id is not None:
            detail["tcId"] = self.tc_id
        detail.update(self.context)
        return detail

    def __str__(self) -> str:
        prefix = f"tcId={self.tc_id}: " if self.tc_id is not None else ""
        return (
            f"{prefix}{self.operation}: OpenSSL={self.openssl_result}, "
            f"GmSSL={self.gmssl_result}"
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run SM2, SM2 encryption, SM3, HMAC-SM3, SM4, or authenticated SM4 test vectors "
            "with OpenSSL, GmSSL, or both."
        )
    )
    parser.add_argument(
        "vector_file",
        type=Path,
        nargs="?",
        help="path to a supported JSON vector file",
    )
    parser.add_argument(
        "--all", action="store_true", help="run every JSON file in the vector directory"
    )
    parser.add_argument(
        "--vector-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "vectors",
        help="directory searched by --all (default: project vectors directory)",
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
    parser.add_argument(
        "--result-dir",
        type=Path,
        help="directory for per-vector reports and summary.json with --all",
    )
    args = parser.parse_args(argv)
    if args.all == (args.vector_file is not None):
        parser.error("provide exactly one vector_file or --all")
    if args.all and args.result_json is not None:
        parser.error("--result-json cannot be used together with --all")
    if not args.all and args.result_dir is not None:
        parser.error("--result-dir can only be used together with --all")
    if args.all and args.result_dir is None:
        parser.error("--all requires --result-dir")
    return args


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
        raise CrossBackendMismatch(operation, openssl_result, gmssl_result)
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
    mismatches: list[dict[str, Any]] | None = None,
) -> int:
    passed = 0

    for test in tests:
        tc_id = test["tcId"]
        backend_mismatch: dict[str, Any] | None = None
        try:
            actual = digest_fn(openssl, bytes.fromhex(test["msg"]))
        except CrossBackendMismatch as error:
            error.set_test_context(tc_id)
            if mismatches is None:
                raise
            backend_mismatch = error.as_error_detail()
            mismatches.append(backend_mismatch)
            actual = error.preferred_result
            print(f"[FAIL] backend mismatch: {error}", file=sys.stderr)
        expected = test["md"]

        matches = actual == expected and backend_mismatch is None
        if results is not None:
            result = {
                    "tcId": tc_id,
                    "status": "passed" if matches else "failed",
                    "expected": expected,
                    "actual": actual,
                }
            if backend_mismatch is not None:
                result["backendMismatch"] = backend_mismatch
            results.append(result)

        if matches:
            passed += 1
            print(f"[PASS] tcId={tc_id}", file=output)
        elif backend_mismatch is not None:
            print(f"[FAIL] tcId={tc_id} backend mismatch", file=output)
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
    mismatches: list[dict[str, Any]] | None = None,
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
            mismatches=mismatches,
        )

    if algorithm == "SM4":
        if not isinstance(document.get("testGroups"), list):
            raise RunnerError("the 'testGroups' field must be an array")
        return sm4_runner.run_tests(
            sm4_runner.extract_tests(document),
            openssl,
            crypt_fn=_crypt_function(backend),
            results=results,
            mismatches=mismatches,
        )

    if algorithm == "HMAC-SM3":
        return hmac_sm3_runner.run_tests(
            hmac_sm3_runner.extract_tests(document),
            openssl,
            hmac_fn=_hmac_function(backend),
            results=results,
            mismatches=mismatches,
        )

    if algorithm == "SM4-CTR-HMAC-SM3":
        encrypt_fn, decrypt_fn = _authenticated_functions(backend)
        return authenticated_sm4_runner.run_tests(
            authenticated_sm4_runner.extract_tests(document),
            openssl,
            encrypt_fn=encrypt_fn,
            decrypt_fn=decrypt_fn,
            results=results,
            mismatches=mismatches,
        )

    if algorithm == "SM2":
        return sm2_runner.run_tests(
            sm2_runner.extract_tests(document),
            backend,
            openssl,
            results=results,
            mismatches=mismatches,
        )

    if algorithm == "SM2-ENCRYPTION":
        return sm2_encryption_runner.run_tests(
            sm2_encryption_runner.extract_tests(document),
            backend,
            openssl,
            results=results,
            mismatches=mismatches,
        )

    name = algorithm or "<missing>"
    raise RunnerError(
        f"unsupported algorithm '{name}'; supported algorithms: "
        "SM2, SM2-ENCRYPTION, SM3, HMAC-SM3, SM4, SM4-CTR-HMAC-SM3"
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
    error: dict[str, Any] | None,
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
    if exit_code in (EXIT_SUCCESS, EXIT_TEST_FAILURE):
        passed = sum(test["status"] == "passed" for test in tests)
        report["summary"] = {
            "total": len(tests),
            "passed": passed,
            "failed": len(tests) - passed,
        }
    if error is not None:
        report["error"] = error
    return report


def _execute_single(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    test_results: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    algorithm: str | None = None
    error_detail: dict[str, Any] | None = None
    try:
        document = load_document(args.vector_file)
        raw_algorithm = document.get("algorithm")
        algorithm = str(raw_algorithm).upper() if raw_algorithm is not None else None
        openssl = resolve_openssl(args.openssl) if args.backend != "gmssl" else ""
        exit_code = run_document(
            document,
            openssl,
            backend=args.backend,
            results=test_results,
            mismatches=mismatches,
        )
        if mismatches:
            exit_code = EXIT_TEST_FAILURE
            error_detail = {
                "type": "backend_mismatches",
                "message": f"{len(mismatches)} backend mismatch(es) detected",
                "count": len(mismatches),
                "mismatches": mismatches,
            }
    except CrossBackendMismatch as error:
        print(f"[FAIL] backend mismatch: {error}", file=sys.stderr)
        exit_code = EXIT_TEST_FAILURE
        error_detail = error.as_error_detail()
    except (
        RunnerError,
        authenticated_sm4.FormatError,
        authenticated_sm4.AuthenticationError,
        authenticated_sm4_runner.RunnerError,
        hmac_sm3_runner.RunnerError,
        sm4_runner.RunnerError,
        sm2_runner.RunnerError,
        sm2_encryption_runner.RunnerError,
        sm2_cipher.CipherError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        exit_code = EXIT_INPUT_ERROR
        error_detail = {"type": "input_error", "message": str(error)}

    return exit_code, _build_report(
        args, algorithm, test_results, exit_code, error_detail
    )


def _batch_exit_code(reports: list[dict[str, Any]]) -> int:
    codes = {report["exitCode"] for report in reports}
    if EXIT_INPUT_ERROR in codes:
        return EXIT_INPUT_ERROR
    if EXIT_TEST_FAILURE in codes:
        return EXIT_TEST_FAILURE
    return EXIT_SUCCESS


def _build_batch_summary(
    args: argparse.Namespace,
    reports: list[dict[str, Any]],
    result_files: list[Path],
) -> dict[str, Any]:
    exit_code = _batch_exit_code(reports)
    passed_files = sum(report["status"] == "passed" for report in reports)
    failed_files = sum(report["status"] == "failed" for report in reports)
    error_files = sum(report["status"] == "error" for report in reports)
    test_summaries = [report["summary"] for report in reports if report["summary"]]
    files: list[dict[str, Any]] = []
    for report, result_file in zip(reports, result_files):
        item: dict[str, Any] = {
            "vectorFile": report["vectorFile"],
            "resultFile": str(result_file.resolve()),
            "algorithm": report["algorithm"],
            "status": report["status"],
            "exitCode": report["exitCode"],
            "summary": report["summary"],
        }
        if "error" in report:
            item["error"] = report["error"]
        files.append(item)

    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "backend": args.backend,
        "vectorDirectory": str(args.vector_dir.resolve()),
        "resultDirectory": str(args.result_dir.resolve()),
        "status": (
            "passed" if exit_code == EXIT_SUCCESS
            else "failed" if exit_code == EXIT_TEST_FAILURE
            else "error"
        ),
        "exitCode": exit_code,
        "summary": {
            "files": len(reports),
            "passedFiles": passed_files,
            "failedFiles": failed_files,
            "errorFiles": error_files,
            "tests": sum(summary["total"] for summary in test_summaries),
            "passedTests": sum(summary["passed"] for summary in test_summaries),
            "failedTests": sum(summary["failed"] for summary in test_summaries),
        },
        "files": files,
    }


def _run_all(args: argparse.Namespace) -> int:
    if not args.vector_dir.exists() or not args.vector_dir.is_dir():
        print(f"Error: vector directory not found: {args.vector_dir}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if args.result_dir.resolve() == args.vector_dir.resolve():
        print("Error: result directory must differ from vector directory", file=sys.stderr)
        return EXIT_INPUT_ERROR
    vector_files = sorted(args.vector_dir.glob("*.json"), key=lambda path: path.name.lower())
    if not vector_files:
        print(f"Error: no JSON vector files found in: {args.vector_dir}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    try:
        args.result_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        print(f"Error: failed to create result directory: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    reports: list[dict[str, Any]] = []
    result_files: list[Path] = []
    for vector_file in vector_files:
        print(f"\n=== {vector_file.name} ===")
        single_args = argparse.Namespace(**vars(args))
        single_args.vector_file = vector_file
        single_args.result_json = None
        exit_code, report = _execute_single(single_args)
        result_file = args.result_dir / f"{vector_file.stem}-{args.backend}.json"
        try:
            _write_json_atomic(result_file, report)
        except RunnerError as error:
            print(f"Error: {error}", file=sys.stderr)
            report = {
                **report,
                "status": "error",
                "exitCode": EXIT_INPUT_ERROR,
                "summary": None,
                "error": {"type": "result_output_error", "message": str(error)},
            }
            exit_code = EXIT_INPUT_ERROR
        reports.append(report)
        result_files.append(result_file)

    summary = _build_batch_summary(args, reports, result_files)
    try:
        _write_json_atomic(args.result_dir / "summary.json", summary)
    except RunnerError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    counts = summary["summary"]
    print(
        "\nBatch total: "
        f"Files={counts['files']}, Passed={counts['passedFiles']}, "
        f"Failed={counts['failedFiles']}, Errors={counts['errorFiles']}, "
        f"Tests={counts['tests']}"
    )
    return summary["exitCode"]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.all:
        return _run_all(args)

    result_path_is_vector = (
        args.result_json is not None
        and args.result_json.resolve() == args.vector_file.resolve()
    )
    if result_path_is_vector:
        print("Error: result JSON path must not overwrite the vector file", file=sys.stderr)
        return EXIT_INPUT_ERROR

    exit_code, report = _execute_single(args)

    if args.result_json is not None:
        try:
            _write_json_atomic(args.result_json, report)
        except RunnerError as error:
            print(f"Error: {error}", file=sys.stderr)
            return EXIT_INPUT_ERROR
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
