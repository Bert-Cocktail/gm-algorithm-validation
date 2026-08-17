#!/usr/bin/env python3
"""Run SM2 signature-verification JSON vectors with OpenSSL and GmSSL."""

from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1
EXIT_INPUT_ERROR = 2
SM2_PUBLIC_KEY_HEX_LENGTH = 130
SM2_ORDER = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
SM2_FIELD = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
SM2_B = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
SUPPORTED_BACKENDS = {"openssl", "gmssl", "cross"}
SUPPORTED_CURVE = "sm2p256v1"
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class RunnerError(Exception):
    """Raised for invalid vectors or an unavailable crypto backend."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run SM2 signature-verification vectors with OpenSSL or GmSSL."
    )
    parser.add_argument("vector_file", type=Path, help="path to an SM2 JSON file")
    parser.add_argument(
        "--backend", choices=sorted(SUPPORTED_BACKENDS), default="cross"
    )
    parser.add_argument(
        "--openssl", default="openssl", help="OpenSSL executable name or path"
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
    if str(document.get("algorithm", "")).upper() != "SM2":
        raise RunnerError("the 'algorithm' field must be 'SM2'")
    if not isinstance(document.get("testGroups"), list):
        raise RunnerError("the 'testGroups' field must be an array")
    return document


def require_hex(
    value: Any, field: str, context: str, *, exact_length: int | None = None
) -> str:
    if not isinstance(value, str):
        raise RunnerError(f"{context}: '{field}' must be a string")
    if len(value) % 2:
        raise RunnerError(f"{context}: '{field}' must contain whole bytes")
    if not HEX_RE.fullmatch(value):
        raise RunnerError(f"{context}: '{field}' contains non-hex characters")
    if exact_length is not None and len(value) != exact_length:
        raise RunnerError(
            f"{context}: '{field}' must contain {exact_length} hex characters"
        )
    return value.lower()


def validate_public_key(value: Any, context: str) -> str:
    public_key = require_hex(
        value,
        "publicKey",
        context,
        exact_length=SM2_PUBLIC_KEY_HEX_LENGTH,
    )
    if not public_key.startswith("04"):
        raise RunnerError(f"{context}: 'publicKey' must be an uncompressed point")
    x = int(public_key[2:66], 16)
    y = int(public_key[66:], 16)
    if x >= SM2_FIELD or y >= SM2_FIELD:
        raise RunnerError(f"{context}: 'publicKey' coordinates are outside the field")
    if (y * y - (pow(x, 3, SM2_FIELD) + SM2_A * x + SM2_B)) % SM2_FIELD:
        raise RunnerError(f"{context}: 'publicKey' is not on the SM2 curve")
    return public_key


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise RunnerError("truncated DER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 2 or offset + 1 + count > len(data):
        raise RunnerError("invalid DER length")
    length_bytes = data[offset + 1 : offset + 1 + count]
    if length_bytes[0] == 0:
        raise RunnerError("non-canonical DER length")
    length = int.from_bytes(length_bytes, "big")
    if length < 0x80:
        raise RunnerError("non-canonical DER length")
    return length, offset + 1 + count


def _read_der_integer(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data) or data[offset] != 0x02:
        raise RunnerError("SM2 signature must contain DER INTEGER values")
    length, start = _read_der_length(data, offset + 1)
    end = start + length
    if length == 0 or end > len(data):
        raise RunnerError("truncated DER INTEGER")
    encoded = data[start:end]
    if encoded[0] & 0x80:
        raise RunnerError("SM2 signature integers must be positive")
    if len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
        raise RunnerError("non-canonical DER INTEGER")
    value = int.from_bytes(encoded, "big")
    if not 1 <= value < SM2_ORDER:
        raise RunnerError("SM2 signature integers must be in the range [1, n-1]")
    return value, end


def der_signature_to_raw(signature: bytes) -> bytes:
    if not signature or signature[0] != 0x30:
        raise RunnerError("SM2 signature must be a DER SEQUENCE")
    sequence_length, offset = _read_der_length(signature, 1)
    if offset + sequence_length != len(signature):
        raise RunnerError("invalid DER signature length")
    r, offset = _read_der_integer(signature, offset)
    s, offset = _read_der_integer(signature, offset)
    if offset != len(signature):
        raise RunnerError("unexpected data after SM2 signature")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return b"\x02" + _encode_der_length(len(encoded)) + encoded


def raw_signature_to_der(signature: bytes) -> bytes:
    if len(signature) != 64:
        raise RunnerError("raw SM2 signature must contain exactly 64 bytes")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not 1 <= r < SM2_ORDER or not 1 <= s < SM2_ORDER:
        raise RunnerError("SM2 signature integers must be in the range [1, n-1]")
    content = _encode_der_integer(r) + _encode_der_integer(s)
    return b"\x30" + _encode_der_length(len(content)) + content


def extract_tests(document: dict[str, Any]) -> list[dict[str, Any]]:
    tests: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for group_index, group in enumerate(document["testGroups"], start=1):
        group_context = f"test group {group_index}"
        if not isinstance(group, dict):
            raise RunnerError(f"{group_context} must be an object")
        if group.get("curve") != SUPPORTED_CURVE:
            raise RunnerError(
                f"{group_context}: 'curve' must be '{SUPPORTED_CURVE}'"
            )
        if str(group.get("signatureFormat", "")).lower() != "der":
            raise RunnerError(f"{group_context}: 'signatureFormat' must be 'der'")
        user_id = require_hex(group.get("userId"), "userId", group_context)
        if not user_id:
            raise RunnerError(f"{group_context}: 'userId' must not be empty")
        if len(user_id) > 8191 * 2:
            raise RunnerError(f"{group_context}: 'userId' is too long for SM2 ENTL")
        try:
            bytes.fromhex(user_id).decode("utf-8")
        except UnicodeDecodeError as error:
            raise RunnerError(f"{group_context}: 'userId' must be valid UTF-8") from error
        group_tests = group.get("tests")
        if not isinstance(group_tests, list):
            raise RunnerError(f"{group_context}: 'tests' must be an array")

        for test_index, test in enumerate(group_tests, start=1):
            context = f"{group_context}, test {test_index}"
            if not isinstance(test, dict):
                raise RunnerError(f"{context} must be an object")
            tc_id = test.get("tcId")
            if not isinstance(tc_id, int) or isinstance(tc_id, bool):
                raise RunnerError(f"{context}: 'tcId' must be an integer")
            if tc_id in seen_ids:
                raise RunnerError(f"duplicate tcId: {tc_id}")
            seen_ids.add(tc_id)
            context = f"tcId={tc_id}"
            if str(test.get("operation", "")).lower() != "verify":
                raise RunnerError(f"{context}: 'operation' must be 'verify'")
            message = require_hex(test.get("msg"), "msg", context)
            msg_len = test.get("msgLen")
            if not isinstance(msg_len, int) or isinstance(msg_len, bool):
                raise RunnerError(f"{context}: 'msgLen' must be an integer")
            actual_bits = len(message) * 4
            if msg_len != actual_bits:
                raise RunnerError(
                    f"{context}: msgLen is {msg_len}, but msg contains {actual_bits} bits"
                )
            public_key = validate_public_key(test.get("publicKey"), context)
            signature = require_hex(test.get("signature"), "signature", context)
            try:
                der_signature_to_raw(bytes.fromhex(signature))
            except RunnerError as error:
                raise RunnerError(f"{context}: invalid 'signature': {error}") from error
            expected = test.get("expected")
            if not isinstance(expected, bool):
                raise RunnerError(f"{context}: 'expected' must be a boolean")
            tests.append(
                {
                    "tcId": tc_id,
                    "operation": "verify",
                    "userId": user_id,
                    "msg": message,
                    "msgLen": msg_len,
                    "publicKey": public_key,
                    "signature": signature,
                    "expected": expected,
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
        raise RunnerError("OpenSSL was not found. Add it to PATH or use --openssl.")
    return resolved


def _public_key_pem(public_key: bytes) -> bytes:
    # SubjectPublicKeyInfo with id-ecPublicKey and the SM2 curve OID.
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a811ccf5501822d034200")
    der = prefix + public_key
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + "\n".join(lines)
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")


def openssl_sm2_verify(
    openssl: str,
    public_key: bytes,
    user_id: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        user_id_text = user_id.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RunnerError("OpenSSL backend requires a UTF-8 SM2 userId") from error
    if "\x00" in user_id_text:
        raise RunnerError("OpenSSL backend does not support NUL in SM2 userId")
    try:
        with tempfile.TemporaryDirectory(prefix="sm2-verify-") as directory:
            root = Path(directory)
            public_path = root / "public.pem"
            signature_path = root / "signature.der"
            message_path = root / "message.bin"
            public_path.write_bytes(_public_key_pem(public_key))
            signature_path.write_bytes(signature)
            message_path.write_bytes(message)
            process = subprocess.run(
                [
                    openssl,
                    "dgst",
                    "-sm3",
                    "-verify",
                    str(public_path),
                    "-signature",
                    str(signature_path),
                    "-sigopt",
                    f"distid:{user_id_text}",
                    str(message_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
    except OSError as error:
        raise RunnerError(f"failed to run OpenSSL SM2 verification: {error}") from error
    if process.returncode == 0:
        return True
    output = (process.stdout + process.stderr).decode("utf-8", errors="replace")
    if process.returncode == 1 and "verification failure" in output.lower():
        return False
    detail = output.strip() or "unknown error"
    raise RunnerError(f"OpenSSL SM2 verification failed: {detail}")


def _gmssl_sm3(data: bytes) -> bytes:
    try:
        from gmssl import func, sm3
    except ImportError as error:
        raise RunnerError("GmSSL backend requires 'gmssl==3.2.2'") from error
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


def gmssl_sm2_verify(
    _openssl: str,
    public_key: bytes,
    user_id: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    try:
        from gmssl import sm2
    except ImportError as error:
        raise RunnerError("GmSSL backend requires 'gmssl==3.2.2'") from error
    entl = (len(user_id) * 8).to_bytes(2, "big")
    curve = sm2.default_ecc_table
    za_input = bytes.fromhex(
        curve["a"] + curve["b"] + curve["g"] + public_key.hex()[2:]
    )
    za = _gmssl_sm3(entl + user_id + za_input)
    digest = _gmssl_sm3(za + message)
    raw_signature = der_signature_to_raw(signature).hex()
    verifier = sm2.CryptSM2(private_key="", public_key=public_key.hex(), asn1=False)
    try:
        return bool(verifier.verify(raw_signature, digest))
    except (TypeError, ValueError, ZeroDivisionError) as error:
        raise RunnerError(f"GmSSL SM2 verification failed: {error}") from error


VerifyFunction = Callable[[str, bytes, bytes, bytes, bytes], bool]


def run_tests(
    tests: list[dict[str, Any]],
    backend: str,
    openssl: str,
    *,
    openssl_verify_fn: VerifyFunction | None = None,
    gmssl_verify_fn: VerifyFunction | None = None,
    output: TextIO = sys.stdout,
    results: list[dict[str, Any]] | None = None,
    mismatches: list[dict[str, Any]] | None = None,
) -> int:
    if backend not in SUPPORTED_BACKENDS:
        raise RunnerError(f"unsupported backend: {backend}")
    if openssl_verify_fn is None:
        openssl_verify_fn = openssl_sm2_verify
    if gmssl_verify_fn is None:
        gmssl_verify_fn = gmssl_sm2_verify
    passed = 0
    for test in tests:
        arguments = (
            openssl,
            bytes.fromhex(test["publicKey"]),
            bytes.fromhex(test["userId"]),
            bytes.fromhex(test["msg"]),
            bytes.fromhex(test["signature"]),
        )
        if backend == "openssl":
            actual = openssl_verify_fn(*arguments)
            mismatch = False
        elif backend == "gmssl":
            actual = gmssl_verify_fn(*arguments)
            mismatch = False
        else:
            openssl_result = openssl_verify_fn(*arguments)
            gmssl_result = gmssl_verify_fn(*arguments)
            mismatch = openssl_result != gmssl_result
            actual = openssl_result
        mismatch_detail: dict[str, Any] | None = None
        if mismatch:
            mismatch_detail = {
                "type": "backend_mismatch",
                "message": (
                    f"tcId={test['tcId']}: SM2 verify: "
                    f"OpenSSL={openssl_result}, GmSSL={gmssl_result}"
                ),
                "operation": "SM2 verify",
                "tcId": test["tcId"],
                "openssl": str(openssl_result),
                "gmssl": str(gmssl_result),
            }
            if mismatches is not None:
                mismatches.append(mismatch_detail)
        success = not mismatch and actual == test["expected"]
        if results is not None:
            result: dict[str, Any] = {
                "tcId": test["tcId"],
                "status": "passed" if success else "failed",
                "expected": test["expected"],
                "actual": actual,
            }
            if mismatch_detail is not None:
                result["backendMismatch"] = mismatch_detail
            results.append(result)
        if success:
            passed += 1
            print(f"[PASS] tcId={test['tcId']} operation=verify", file=output)
        elif mismatch:
            print(
                f"[FAIL] tcId={test['tcId']} backend mismatch: "
                f"OpenSSL={openssl_result} GmSSL={gmssl_result}",
                file=output,
            )
        else:
            print(
                f"[FAIL] tcId={test['tcId']} expected={test['expected']} "
                f"actual={actual}",
                file=output,
            )
    failed = len(tests) - passed
    print(f"Passed: {passed}", file=output)
    print(f"Failed: {failed}", file=output)
    return EXIT_SUCCESS if failed == 0 else EXIT_TEST_FAILURE


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        document = load_vectors(args.vector_file)
        tests = extract_tests(document)
        openssl = (
            resolve_openssl(args.openssl)
            if args.backend in {"openssl", "cross"}
            else args.openssl
        )
        return run_tests(tests, args.backend, openssl)
    except RunnerError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
