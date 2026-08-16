#!/usr/bin/env python3
"""Process local ACVP-like request files with the project crypto backends."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

import authenticated_sm4
import authenticated_sm4_runner
import hmac_sm3_runner
import runner
import sm4_runner


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
ACV_VERSION = "1.0"
PROJECT_ROOT = Path(__file__).resolve().parent
REQUEST_SCHEMA = PROJECT_ROOT / "acvp" / "schemas" / "request-schema.json"
RESPONSE_SCHEMA = PROJECT_ROOT / "acvp" / "schemas" / "response-schema.json"
CAPABILITIES_SCHEMA = PROJECT_ROOT / "acvp" / "schemas" / "capabilities-schema.json"
SUMMARY_SCHEMA = PROJECT_ROOT / "acvp" / "schemas" / "batch-summary-schema.json"

TEST_TYPES = [
    {"name": "AFT", "status": "supported"},
    {"name": "MCT", "status": "recognized-not-implemented"},
    {"name": "GDT", "status": "recognized-not-implemented"},
]

CAPABILITIES: dict[str, Any] = {
    "acvVersion": ACV_VERSION,
    "localFormat": True,
    "algorithms": [
        {
            "algorithm": "SM3",
            "identifierMapping": {
                "localAlgorithm": "SM3",
                "standardIdentifier": "GB/T 32905-2016",
                "acvpAlgorithm": None,
                "acvpStatus": "no-identifier-asserted",
            },
            "revision": "GB/T 32905-2016",
            "testTypes": TEST_TYPES,
            "messageLength": {"min": 0, "max": 1048576, "increment": 8},
            "digestLength": 256,
        },
        {
            "algorithm": "HMAC-SM3",
            "identifierMapping": {
                "localAlgorithm": "HMAC-SM3",
                "standardIdentifier": "local HMAC construction using SM3",
                "acvpAlgorithm": None,
                "acvpStatus": "no-identifier-asserted",
            },
            "revision": "local-experiment",
            "testTypes": TEST_TYPES,
            "keyLength": {"min": 8, "max": 4096, "increment": 8},
            "messageLength": {"min": 0, "max": 1048576, "increment": 8},
            "macLength": 256,
        },
        {
            "algorithm": "SM4",
            "identifierMapping": {
                "localAlgorithm": "SM4",
                "standardIdentifier": "GB/T 32907-2016",
                "acvpAlgorithm": None,
                "acvpStatus": "no-identifier-asserted",
            },
            "revision": "GB/T 32907-2016",
            "testTypes": TEST_TYPES,
            "directions": ["encrypt", "decrypt"],
            "keyLength": 128,
            "modes": {
                "ECB": {"payloadLength": {"min": 128, "increment": 128}},
                "CBC": {"ivLength": 128, "payloadLength": {"min": 128, "increment": 128}},
                "CTR": {"ivLength": 128, "payloadLength": {"min": 8, "increment": 8}},
            },
        },
        {
            "algorithm": authenticated_sm4.ALGORITHM,
            "identifierMapping": {
                "localAlgorithm": authenticated_sm4.ALGORITHM,
                "standardIdentifier": "local Encrypt-then-MAC experiment",
                "acvpAlgorithm": None,
                "acvpStatus": "local-only",
            },
            "revision": "local-experiment",
            "testTypes": TEST_TYPES,
            "directions": ["encrypt"],
            "sm4KeyLength": 128,
            "hmacKeyLength": 256,
            "ivLength": 128,
            "tagLength": 256,
        },
    ],
}


class AdapterError(Exception):
    """Raised when an ACVP-like request is malformed or cannot be processed."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Process a local ACVP-like request and write its response."
    )
    parser.add_argument("request_file", type=Path, nargs="?")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--all", action="store_true", help="process all request files")
    parser.add_argument("--request-dir", type=Path)
    parser.add_argument("--response-dir", type=Path)
    parser.add_argument(
        "--capabilities",
        action="store_true",
        help="print the local implementation capabilities as JSON",
    )
    parser.add_argument(
        "--backend",
        choices=("openssl", "gmssl", "cross"),
        default="openssl",
    )
    parser.add_argument("--openssl", default="openssl")
    return parser.parse_args(argv)


def _load_schema(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as schema_file:
            schema = json.load(schema_file)
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError(f"cannot load JSON Schema {path.name}: {error}") from error
    if not isinstance(schema, dict):
        raise AdapterError(f"JSON Schema {path.name} must contain an object")
    return schema


def validate_schema(instance: Any, schema_path: Path, label: str) -> None:
    try:
        validator = jsonschema.Draft202012Validator(_load_schema(schema_path))
        error = next(iter(validator.iter_errors(instance)), None)
    except jsonschema.SchemaError as schema_error:
        raise AdapterError(
            f"invalid {label} JSON Schema: {schema_error.message}"
        ) from schema_error
    if error is not None:
        location = "/".join(str(part) for part in error.absolute_path) or "<root>"
        raise AdapterError(f"{label} schema error at {location}: {error.message}")


def load_request(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8-sig") as request_file:
            envelope = json.load(request_file)
    except FileNotFoundError as error:
        raise AdapterError(f"request file not found: {path}") from error
    except (PermissionError, OSError) as error:
        raise AdapterError(f"cannot read request file: {error}") from error
    except json.JSONDecodeError as error:
        raise AdapterError(
            f"invalid JSON at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error

    validate_schema(envelope, REQUEST_SCHEMA, "request")
    version, request = envelope
    return version, request


def _validate_group_parameters(request: dict[str, Any]) -> None:
    algorithm = request["algorithm"].upper()
    capability = next(
        item for item in CAPABILITIES["algorithms"] if item["algorithm"] == algorithm
    )
    supported_types = {
        item["name"] for item in capability["testTypes"] if item["status"] == "supported"
    }
    for group in request["testGroups"]:
        tg_id = group["tgId"]
        test_type = group["testType"]
        if test_type not in supported_types:
            raise AdapterError(
                f"tgId={tg_id}: testType '{test_type}' is recognized but not implemented; "
                f"supported testTypes: {', '.join(sorted(supported_types))}"
            )
        if algorithm == "SM3":
            for test in group["tests"]:
                _validate_range(
                    test["msgLen"], capability["messageLength"], "msgLen", test["tcId"]
                )
        elif algorithm == "HMAC-SM3":
            _validate_range(group["keyLen"], capability["keyLength"], "keyLen", tg_id)
            for test in group["tests"]:
                if len(test["key"]) * 4 != group["keyLen"]:
                    raise AdapterError(
                        f"tcId={test['tcId']}: key length does not match group keyLen"
                    )
                _validate_range(
                    test["msgLen"], capability["messageLength"], "msgLen", test["tcId"]
                )
            if group["macLen"] != capability["macLength"]:
                raise AdapterError(
                    f"tgId={tg_id}: HMAC-SM3 macLen must be {capability['macLength']}"
                )
        elif algorithm == "SM4":
            mode = group["mode"]
            direction = group["direction"]
            if group["keyLen"] != capability["keyLength"]:
                raise AdapterError(
                    f"tgId={tg_id}: SM4 keyLen must be {capability['keyLength']}"
                )
            if direction not in capability["directions"] or mode not in capability["modes"]:
                raise AdapterError(f"tgId={tg_id}: request exceeds SM4 capabilities")
            mode_capability = capability["modes"][mode]
            input_field = "pt" if direction == "encrypt" else "ct"
            for test in group["tests"]:
                if len(test["key"]) * 4 != capability["keyLength"]:
                    raise AdapterError(
                        f"tcId={test['tcId']}: key length exceeds declared capability"
                    )
                payload_length = len(test[input_field]) * 4
                _validate_range(
                    payload_length,
                    mode_capability["payloadLength"],
                    "payload length",
                    test["tcId"],
                )
                if "ivLength" in mode_capability and len(test["iv"]) * 4 != mode_capability["ivLength"]:
                    raise AdapterError(
                        f"tcId={test['tcId']}: IV length exceeds declared capability"
                    )
        elif algorithm == authenticated_sm4.ALGORITHM:
            if group["direction"] not in capability["directions"]:
                raise AdapterError(
                    f"tgId={tg_id}: authenticated experiment supports encrypt only"
                )
            expected = {
                "sm4KeyLen": capability["sm4KeyLength"],
                "hmacKeyLen": capability["hmacKeyLength"],
                "tagLen": capability["tagLength"],
            }
            for field, value in expected.items():
                if group[field] != value:
                    raise AdapterError(f"tgId={tg_id}: {field} must be {value}")
            for test in group["tests"]:
                actual_lengths = {
                    "sm4KeyLength": len(test["sm4Key"]) * 4,
                    "hmacKeyLength": len(test["hmacKey"]) * 4,
                    "ivLength": len(test["iv"]) * 4,
                }
                for field, actual in actual_lengths.items():
                    if actual != capability[field]:
                        raise AdapterError(
                            f"tcId={test['tcId']}: {field} exceeds declared capability"
                        )


def _validate_range(value: int, limits: dict[str, int], field: str, identifier: int) -> None:
    minimum = limits["min"]
    maximum = limits.get("max")
    increment = limits["increment"]
    if value < minimum or (maximum is not None and value > maximum):
        upper = str(maximum) if maximum is not None else "unbounded"
        raise AdapterError(
            f"id={identifier}: {field}={value} is outside capability range {minimum}..{upper}"
        )
    if (value - minimum) % increment != 0:
        raise AdapterError(
            f"id={identifier}: {field}={value} does not match increment {increment}"
        )


def _validate_group_ids(request: dict[str, Any]) -> None:
    seen_groups: set[int] = set()
    seen_tests: set[int] = set()
    for group_index, group in enumerate(request["testGroups"], start=1):
        if not isinstance(group, dict):
            raise AdapterError(f"test group {group_index} must be an object")
        tg_id = group.get("tgId")
        if not isinstance(tg_id, int) or isinstance(tg_id, bool):
            raise AdapterError(f"test group {group_index}: 'tgId' must be an integer")
        if tg_id in seen_groups:
            raise AdapterError(f"duplicate tgId: {tg_id}")
        seen_groups.add(tg_id)
        tests = group.get("tests")
        if not isinstance(tests, list) or not tests:
            raise AdapterError(f"tgId={tg_id}: 'tests' must be a non-empty array")
        for test_index, test in enumerate(tests, start=1):
            if not isinstance(test, dict):
                raise AdapterError(f"tgId={tg_id}, test {test_index} must be an object")
            tc_id = test.get("tcId")
            if not isinstance(tc_id, int) or isinstance(tc_id, bool):
                raise AdapterError(f"tgId={tg_id}, test {test_index}: invalid tcId")
            if tc_id in seen_tests:
                raise AdapterError(f"duplicate tcId: {tc_id}")
            seen_tests.add(tc_id)


def _call_cross_aware(
    operation: Callable[..., Any],
    tc_id: int,
    mismatches: list[dict[str, Any]],
    *args: Any,
    context: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Any:
    try:
        return operation(*args, **kwargs)
    except runner.CrossBackendMismatch as error:
        error.set_test_context(tc_id, **(context or {}))
        mismatches.append(error.as_error_detail())
        return error.preferred_result


def _sm3_response(
    request: dict[str, Any], openssl: str, backend: str, mismatches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    validation = {"algorithm": "SM3", "testGroups": []}
    for group in request["testGroups"]:
        validation["testGroups"].append(
            {
                "tests": [
                    {**test, "md": "00" * 32}
                    for test in group["tests"]
                ]
            }
        )
    tests = runner.extract_tests(validation)
    digest_fn = runner._digest_function(backend)
    by_id = {test["tcId"]: test for test in tests}
    response_groups = []
    for group in request["testGroups"]:
        response_tests = []
        for original in group["tests"]:
            test = by_id[original["tcId"]]
            digest = _call_cross_aware(
                digest_fn,
                test["tcId"],
                mismatches,
                openssl,
                bytes.fromhex(test["msg"]),
            )
            response_tests.append({"tcId": test["tcId"], "md": digest})
        response_groups.append({"tgId": group["tgId"], "tests": response_tests})
    return response_groups


def _hmac_response(
    request: dict[str, Any], openssl: str, backend: str, mismatches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    validation = {"algorithm": "HMAC-SM3", "testGroups": []}
    for group in request["testGroups"]:
        validation["testGroups"].append(
            {
                "tests": [
                    {**test, "tag": "00" * 32}
                    for test in group["tests"]
                ]
            }
        )
    tests = hmac_sm3_runner.extract_tests(validation)
    hmac_fn = runner._hmac_function(backend)
    by_id = {test["tcId"]: test for test in tests}
    response_groups = []
    for group in request["testGroups"]:
        response_tests = []
        for original in group["tests"]:
            test = by_id[original["tcId"]]
            mac = _call_cross_aware(
                hmac_fn,
                test["tcId"],
                mismatches,
                openssl,
                test["key"],
                bytes.fromhex(test["msg"]),
            )
            response_tests.append({"tcId": test["tcId"], "mac": mac})
        response_groups.append({"tgId": group["tgId"], "tests": response_tests})
    return response_groups


def _sm4_response(
    request: dict[str, Any], openssl: str, backend: str, mismatches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    validation_groups = []
    for group in request["testGroups"]:
        direction = str(group.get("direction", "")).lower()
        input_field = "pt" if direction == "encrypt" else "ct"
        validation_tests = []
        for test in group["tests"]:
            value = test.get(input_field)
            validation_tests.append(
                {
                    **test,
                    "pt": value,
                    "ct": value,
                }
            )
        validation_groups.append(
            {
                "mode": group.get("mode"),
                "direction": direction,
                "tests": validation_tests,
            }
        )
    tests = sm4_runner.extract_tests(
        {"algorithm": "SM4", "testGroups": validation_groups}
    )
    crypt_fn = runner._crypt_function(backend)
    by_id = {test["tcId"]: test for test in tests}
    response_groups = []
    for group in request["testGroups"]:
        response_tests = []
        for original in group["tests"]:
            test = by_id[original["tcId"]]
            input_field = "pt" if test["direction"] == "encrypt" else "ct"
            output_field = "ct" if test["direction"] == "encrypt" else "pt"
            result = _call_cross_aware(
                crypt_fn,
                test["tcId"],
                mismatches,
                openssl,
                test["mode"],
                test["direction"],
                test["key"],
                test["iv"],
                bytes.fromhex(test[input_field]),
                context={"mode": test["mode"], "direction": test["direction"]},
            )
            response_tests.append({"tcId": test["tcId"], output_field: result.hex()})
        response_groups.append({"tgId": group["tgId"], "tests": response_tests})
    return response_groups


def _authenticated_response(
    request: dict[str, Any], openssl: str, backend: str, mismatches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    validation = {"algorithm": authenticated_sm4.ALGORITHM, "testGroups": []}
    for group in request["testGroups"]:
        validation["testGroups"].append(
            {
                "tests": [
                    {**test, "ct": test.get("pt"), "tag": "00" * 32}
                    for test in group["tests"]
                ]
            }
        )
    tests = authenticated_sm4_runner.extract_tests(validation)
    encrypt_fn, _decrypt_fn = runner._authenticated_functions(backend)
    by_id = {test["tcId"]: test for test in tests}
    response_groups = []
    for group in request["testGroups"]:
        response_tests = []
        for original in group["tests"]:
            test = by_id[original["tcId"]]
            package = _call_cross_aware(
                encrypt_fn,
                test["tcId"],
                mismatches,
                openssl,
                test["sm4Key"],
                test["hmacKey"],
                bytes.fromhex(test["pt"]),
                iv=bytes.fromhex(test["iv"]),
                context={"algorithm": authenticated_sm4.ALGORITHM},
            )
            response_tests.append(
                {
                    "tcId": test["tcId"],
                    "ct": package["ciphertext"],
                    "tag": package["tag"],
                }
            )
        response_groups.append({"tgId": group["tgId"], "tests": response_tests})
    return response_groups


def process_request(
    version: dict[str, Any], request: dict[str, Any], openssl: str, backend: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _validate_group_ids(request)
    _validate_group_parameters(request)
    algorithm = str(request.get("algorithm", "")).upper()
    mismatches: list[dict[str, Any]] = []
    handlers = {
        "SM3": _sm3_response,
        "HMAC-SM3": _hmac_response,
        "SM4": _sm4_response,
        authenticated_sm4.ALGORITHM: _authenticated_response,
    }
    if algorithm not in handlers:
        raise AdapterError(f"unsupported algorithm: {algorithm or '<missing>'}")
    groups = handlers[algorithm](request, openssl, backend, mismatches)
    response: dict[str, Any] = {
        "vsId": request["vsId"],
        "algorithm": algorithm,
        "testGroups": groups,
    }
    if mismatches:
        response["localDiagnostics"] = {
            "backend": backend,
            "mismatches": mismatches,
        }
    envelope = [version, response]
    validate_schema(envelope, RESPONSE_SCHEMA, "response")
    return envelope, mismatches


def _atomic_write_json(path: Path, value: Any) -> None:
    if not path.parent.exists() or not path.parent.is_dir():
        raise AdapterError(f"output directory not found: {path.parent}")
    encoded = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as response_file:
            response_file.write(encoded)
            response_file.flush()
            os.fsync(response_file.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as error:
        raise AdapterError(f"failed to write response: {error}") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def write_response(path: Path, request_path: Path, response: list[dict[str, Any]]) -> None:
    if path.resolve() == request_path.resolve():
        raise AdapterError("output path must not overwrite the request file")
    _atomic_write_json(path, response)


PROCESS_ERRORS = (
    AdapterError,
    runner.RunnerError,
    sm4_runner.RunnerError,
    hmac_sm3_runner.RunnerError,
    authenticated_sm4_runner.RunnerError,
    authenticated_sm4.FormatError,
)


def _count_tests(request: dict[str, Any]) -> int:
    return sum(len(group["tests"]) for group in request["testGroups"])


def _batch_response_name(request_path: Path) -> str:
    stem = request_path.stem
    response_stem = stem[:-8] + "-response" if stem.endswith("-request") else stem + "-response"
    return response_stem + ".json"


def run_batch(args: argparse.Namespace) -> int:
    if args.request_dir is None or args.response_dir is None:
        raise AdapterError("--all requires --request-dir and --response-dir")
    request_dir = args.request_dir.resolve()
    response_dir = args.response_dir.resolve()
    if not request_dir.is_dir():
        raise AdapterError(f"request directory not found: {args.request_dir}")
    if request_dir == response_dir:
        raise AdapterError("request and response directories must be different")
    response_dir.mkdir(parents=True, exist_ok=True)
    request_paths = sorted(request_dir.glob("*-request.json"), key=lambda path: path.name)
    if not request_paths:
        raise AdapterError(f"no *-request.json files found in: {args.request_dir}")

    response_names = [_batch_response_name(path) for path in request_paths]
    if len(response_names) != len(set(response_names)):
        raise AdapterError("request filenames produce duplicate response filenames")

    openssl = runner.resolve_openssl(args.openssl) if args.backend != "gmssl" else ""
    files: list[dict[str, Any]] = []
    seen_vs_ids: set[int] = set()
    passed_files = failed_files = error_files = total_tests = mismatch_count = 0

    for request_path, response_name in zip(request_paths, response_names):
        response_path = response_dir / response_name
        item: dict[str, Any] = {
            "requestFile": request_path.name,
            "responseFile": response_name,
        }
        print(f"\n=== {request_path.name} ===")
        try:
            version, request = load_request(request_path)
            item.update(
                {
                    "vsId": request["vsId"],
                    "algorithm": request["algorithm"],
                    "tests": _count_tests(request),
                }
            )
            if request["vsId"] in seen_vs_ids:
                raise AdapterError(f"duplicate vsId across request files: {request['vsId']}")
            seen_vs_ids.add(request["vsId"])
            response, mismatches = process_request(version, request, openssl, args.backend)
            write_response(response_path, request_path, response)
            total_tests += item["tests"]
            mismatch_count += len(mismatches)
            if mismatches:
                item.update({"status": "failed", "exitCode": EXIT_TEST_FAILURE, "mismatches": len(mismatches)})
                failed_files += 1
            else:
                item.update({"status": "passed", "exitCode": EXIT_SUCCESS, "mismatches": 0})
                passed_files += 1
        except PROCESS_ERRORS as error:
            print(f"Error: {error}", file=sys.stderr)
            item.update(
                {
                    "status": "error",
                    "exitCode": EXIT_INPUT_ERROR,
                    "error": str(error),
                }
            )
            error_files += 1
        files.append(item)

    exit_code = (
        EXIT_INPUT_ERROR
        if error_files
        else EXIT_TEST_FAILURE if failed_files else EXIT_SUCCESS
    )
    status = "error" if error_files else "failed" if failed_files else "passed"
    summary = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "backend": args.backend,
        "status": status,
        "exitCode": exit_code,
        "summary": {
            "files": len(files),
            "passedFiles": passed_files,
            "failedFiles": failed_files,
            "errorFiles": error_files,
            "tests": total_tests,
            "backendMismatches": mismatch_count,
        },
        "files": files,
    }
    validate_schema(summary, SUMMARY_SCHEMA, "batch summary")
    _atomic_write_json(response_dir / "summary.json", summary)
    print(
        f"\nBatch total: Files={len(files)}, Passed={passed_files}, "
        f"Failed={failed_files}, Errors={error_files}, Tests={total_tests}, "
        f"Mismatches={mismatch_count}"
    )
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.capabilities:
            if any(
                value is not None
                for value in (args.request_file, args.output, args.request_dir, args.response_dir)
            ) or args.all:
                raise AdapterError(
                    "--capabilities cannot be combined with request or batch options"
                )
            validate_schema(CAPABILITIES, CAPABILITIES_SCHEMA, "capabilities")
            print(json.dumps(CAPABILITIES, indent=2, ensure_ascii=False))
            return EXIT_SUCCESS
        if args.all:
            if args.request_file is not None or args.output is not None:
                raise AdapterError("--all cannot be combined with request_file or --output")
            return run_batch(args)
        if args.request_dir is not None or args.response_dir is not None:
            raise AdapterError("--request-dir and --response-dir require --all")
        if args.request_file is None or args.output is None:
            raise AdapterError("request_file and --output are required")
        version, request = load_request(args.request_file)
        openssl = runner.resolve_openssl(args.openssl) if args.backend != "gmssl" else ""
        response, mismatches = process_request(version, request, openssl, args.backend)
        write_response(args.output, args.request_file, response)
        return EXIT_TEST_FAILURE if mismatches else EXIT_SUCCESS
    except PROCESS_ERRORS as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
