"""Run SM2 encryption, decryption, and ciphertext-format vectors."""

from __future__ import annotations

import sys
from typing import Any, TextIO

import sm2_cipher


EXIT_SUCCESS = 0
EXIT_TEST_FAILURE = 1


class RunnerError(ValueError):
    """Raised when an SM2 encryption vector is malformed."""


def _hex(value: Any, field: str, tc_id: Any, length: int | None = None) -> str:
    if not isinstance(value, str) or len(value) % 2:
        raise RunnerError(f"tcId={tc_id}: '{field}' must contain whole hexadecimal bytes")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise RunnerError(f"tcId={tc_id}: '{field}' contains non-hex characters") from error
    if length is not None and len(raw) != length:
        raise RunnerError(f"tcId={tc_id}: '{field}' must contain exactly {length} bytes")
    return raw.hex()


def extract_tests(document: dict[str, Any]) -> list[dict[str, Any]]:
    if str(document.get("algorithm", "")).upper() != "SM2-ENCRYPTION":
        raise RunnerError("the 'algorithm' field must be 'SM2-ENCRYPTION'")
    groups = document.get("testGroups")
    if not isinstance(groups, list):
        raise RunnerError("the 'testGroups' field must be an array")
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for group_index, group in enumerate(groups, 1):
        if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
            raise RunnerError(f"test group {group_index}: 'tests' must be an array")
        curve = group.get("curve")
        for test in group["tests"]:
            if not isinstance(test, dict):
                raise RunnerError(f"test group {group_index}: each test must be an object")
            tc_id = test.get("tcId")
            if not isinstance(tc_id, int) or isinstance(tc_id, bool) or tc_id in seen:
                raise RunnerError(f"invalid or duplicate tcId: {tc_id}")
            seen.add(tc_id)
            operation = test.get("operation")
            if operation not in {"decrypt", "encryptRoundTrip", "convert"}:
                raise RunnerError(f"tcId={tc_id}: unsupported operation '{operation}'")
            item = {"tcId": tc_id, "operation": operation, "curve": curve}
            if operation == "encryptRoundTrip":
                if curve != "sm2p256v1":
                    raise RunnerError(f"tcId={tc_id}: encryption requires sm2p256v1")
                item["publicKey"] = _hex(test.get("publicKey"), "publicKey", tc_id, 65)
                item["privateKey"] = _hex(test.get("privateKey"), "privateKey", tc_id, 32)
                item["msg"] = _hex(test.get("msg"), "msg", tc_id)
                if not item["msg"]:
                    raise RunnerError(f"tcId={tc_id}: 'msg' must not be empty")
            elif operation == "decrypt":
                if curve != "sm2p256v1":
                    raise RunnerError(f"tcId={tc_id}: decryption requires sm2p256v1")
                item["privateKey"] = _hex(test.get("privateKey"), "privateKey", tc_id, 32)
                item["ciphertext"] = _hex(test.get("ciphertext"), "ciphertext", tc_id)
                item["ciphertextFormat"] = str(test.get("ciphertextFormat", "")).lower()
                item["msg"] = _hex(test.get("msg"), "msg", tc_id)
                item["expected"] = test.get("expected", True)
                if not isinstance(item["expected"], bool):
                    raise RunnerError(f"tcId={tc_id}: 'expected' must be a boolean")
            else:
                item["ciphertext"] = _hex(test.get("ciphertext"), "ciphertext", tc_id)
                item["sourceFormat"] = str(test.get("sourceFormat", "")).lower()
                item["targetFormat"] = str(test.get("targetFormat", "")).lower()
                item["expectedCiphertext"] = _hex(
                    test.get("expectedCiphertext"), "expectedCiphertext", tc_id
                )
            result.append(item)
    if not result:
        raise RunnerError("the vector file contains no tests")
    return result


def run_tests(
    tests: list[dict[str, Any]], backend: str, openssl: str, *,
    output: TextIO = sys.stdout, results: list[dict[str, Any]] | None = None,
    mismatches: list[dict[str, Any]] | None = None,
) -> int:
    passed = 0
    for test in tests:
        tc_id = test["tcId"]
        try:
            if test["operation"] == "convert":
                actual = sm2_cipher.convert_ciphertext(
                    bytes.fromhex(test["ciphertext"]), test["sourceFormat"], test["targetFormat"]
                ).hex()
                ok = actual == test["expectedCiphertext"]
            elif test["operation"] == "decrypt":
                original = bytes.fromhex(test["ciphertext"])
                expected_success = test["expected"]
                recovered: list[bytes] = []
                rejected = 0
                for selected in (["openssl", "gmssl"] if backend == "cross" else [backend]):
                    try:
                        if selected == "openssl":
                            raw = sm2_cipher.convert_ciphertext(original, test["ciphertextFormat"], "der")
                            recovered.append(sm2_cipher.openssl_decrypt(openssl, bytes.fromhex(test["privateKey"]), raw))
                        else:
                            raw = sm2_cipher.convert_ciphertext(original, test["ciphertextFormat"], "c1c3c2")
                            recovered.append(sm2_cipher.gmssl_decrypt("", bytes.fromhex(test["privateKey"]), raw))
                    except sm2_cipher.CipherError:
                        rejected += 1
                if expected_success:
                    ok = not rejected and all(value.hex() == test["msg"] for value in recovered)
                    actual = recovered[0].hex() if recovered else "rejected"
                else:
                    expected_count = 2 if backend == "cross" else 1
                    ok = rejected == expected_count
                    actual = "rejected" if ok else "accepted"
            else:
                msg = bytes.fromhex(test["msg"])
                selected_backends = ["openssl", "gmssl"] if backend == "cross" else [backend]
                recovered = []
                for selected in selected_backends:
                    if selected == "openssl":
                        cipher = sm2_cipher.openssl_encrypt(openssl, bytes.fromhex(test["publicKey"]), msg)
                        recovered.append(sm2_cipher.openssl_decrypt(openssl, bytes.fromhex(test["privateKey"]), cipher))
                    else:
                        cipher = sm2_cipher.gmssl_encrypt("", bytes.fromhex(test["publicKey"]), msg)
                        recovered.append(sm2_cipher.gmssl_decrypt("", bytes.fromhex(test["privateKey"]), cipher))
                ok = all(value == msg for value in recovered)
                actual = recovered[0].hex()
        except sm2_cipher.CipherError:
            if test["operation"] == "decrypt" and not test.get("expected", True):
                ok, actual = True, "rejected"
            else:
                ok, actual = False, "error"
        if results is not None:
            results.append({"tcId": tc_id, "status": "passed" if ok else "failed", "actual": actual})
        print(f"[{'PASS' if ok else 'FAIL'}] tcId={tc_id}", file=output)
        passed += int(ok)
    print(f"\nTotal: {len(tests)}, Passed: {passed}, Failed: {len(tests)-passed}", file=output)
    return EXIT_SUCCESS if passed == len(tests) else EXIT_TEST_FAILURE
