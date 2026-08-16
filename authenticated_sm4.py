#!/usr/bin/env python3
"""Shared format rules for the authenticated SM4-CTR experiment."""

from __future__ import annotations

import re
import hmac
import secrets
from collections.abc import Callable
from typing import Any, Optional, TypedDict

import hmac_sm3_runner
import sm4_runner


VERSION = 1
ALGORITHM = "SM4-CTR-HMAC-SM3"
MAGIC = b"GMENC"
SM4_KEY_BYTES = 16
HMAC_KEY_BYTES = 32
IV_BYTES = 16
TAG_BYTES = 32
PACKAGE_FIELDS = {"version", "algorithm", "iv", "ciphertext", "tag"}
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


class FormatError(ValueError):
    """Raised when a key or authenticated package violates the format."""


class AuthenticationError(Exception):
    """Raised when an authenticated package has an invalid tag."""


class AuthenticatedPackage(TypedDict):
    version: int
    algorithm: str
    iv: str
    ciphertext: str
    tag: str


def normalize_hex(
    value: Any,
    field: str,
    *,
    exact_bytes: int | None = None,
    nonempty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise FormatError(f"'{field}' must be a hexadecimal string")
    if len(value) % 2 != 0:
        raise FormatError(f"'{field}' must contain whole bytes")
    if not HEX_RE.fullmatch(value):
        raise FormatError(f"'{field}' contains non-hex characters")
    if nonempty and not value:
        raise FormatError(f"'{field}' must not be empty")
    if exact_bytes is not None and len(value) != exact_bytes * 2:
        raise FormatError(
            f"'{field}' must contain exactly {exact_bytes} bytes "
            f"({exact_bytes * 2} hexadecimal characters)"
        )
    return value.lower()


def validate_keys(sm4_key_hex: Any, hmac_key_hex: Any) -> tuple[str, str]:
    """Validate and normalize the two independent experiment keys."""
    sm4_key = normalize_hex(
        sm4_key_hex, "sm4Key", exact_bytes=SM4_KEY_BYTES
    )
    hmac_key = normalize_hex(
        hmac_key_hex, "hmacKey", exact_bytes=HMAC_KEY_BYTES
    )
    return sm4_key, hmac_key


def build_authenticated_data(
    version: int,
    algorithm: str,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """Build the canonical bytes covered by HMAC-SM3."""
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        raise FormatError(f"unsupported version: {version!r}")
    if algorithm != ALGORITHM:
        raise FormatError(f"unsupported algorithm: {algorithm!r}")
    if not isinstance(iv, bytes) or len(iv) != IV_BYTES:
        raise FormatError(f"'iv' must contain exactly {IV_BYTES} bytes")
    if not isinstance(ciphertext, bytes):
        raise FormatError("'ciphertext' must be bytes")

    return (
        MAGIC
        + bytes([version])
        + ALGORITHM.encode("ascii")
        + iv
        + len(ciphertext).to_bytes(8, "big")
        + ciphertext
    )


def validate_package(package: Any) -> AuthenticatedPackage:
    """Validate and normalize the JSON-friendly authenticated package."""
    if not isinstance(package, dict):
        raise FormatError("authenticated package must be an object")

    fields = set(package)
    missing = PACKAGE_FIELDS - fields
    extra = fields - PACKAGE_FIELDS
    if missing:
        raise FormatError(f"missing package field(s): {', '.join(sorted(missing))}")
    if extra:
        raise FormatError(f"unknown package field(s): {', '.join(sorted(extra))}")

    version = package["version"]
    algorithm = package["algorithm"]
    if not isinstance(version, int) or isinstance(version, bool) or version != VERSION:
        raise FormatError(f"unsupported version: {version!r}")
    if algorithm != ALGORITHM:
        raise FormatError(f"unsupported algorithm: {algorithm!r}")

    return {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "iv": normalize_hex(package["iv"], "iv", exact_bytes=IV_BYTES),
        "ciphertext": normalize_hex(package["ciphertext"], "ciphertext"),
        "tag": normalize_hex(package["tag"], "tag", exact_bytes=TAG_BYTES),
    }


def package_authenticated_data(package: Any) -> bytes:
    """Validate a package and return the canonical bytes covered by its tag."""
    normalized = validate_package(package)
    return build_authenticated_data(
        normalized["version"],
        normalized["algorithm"],
        bytes.fromhex(normalized["iv"]),
        bytes.fromhex(normalized["ciphertext"]),
    )


CryptFunction = Callable[[str, str, str, str, Optional[str], bytes], bytes]
HmacFunction = Callable[[str, str, bytes], str]


def encrypt_and_authenticate(
    openssl: str,
    sm4_key_hex: Any,
    hmac_key_hex: Any,
    plaintext: bytes,
    *,
    iv: bytes | None = None,
    crypt_fn: CryptFunction = sm4_runner.sm4_crypt,
    hmac_fn: HmacFunction = hmac_sm3_runner.hmac_sm3,
) -> AuthenticatedPackage:
    """Encrypt plaintext with SM4-CTR, then authenticate the package fields."""
    sm4_key, hmac_key = validate_keys(sm4_key_hex, hmac_key_hex)
    if not isinstance(plaintext, bytes):
        raise FormatError("'plaintext' must be bytes")

    if iv is None:
        iv_bytes = secrets.token_bytes(IV_BYTES)
    elif isinstance(iv, bytes) and len(iv) == IV_BYTES:
        iv_bytes = iv
    else:
        raise FormatError(f"'iv' must contain exactly {IV_BYTES} bytes")

    ciphertext = crypt_fn(
        openssl, "CTR", "encrypt", sm4_key, iv_bytes.hex(), plaintext
    )
    authenticated_data = build_authenticated_data(
        VERSION, ALGORITHM, iv_bytes, ciphertext
    )
    tag = normalize_hex(
        hmac_fn(openssl, hmac_key, authenticated_data),
        "tag",
        exact_bytes=TAG_BYTES,
    )
    return {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "iv": iv_bytes.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag,
    }


def verify_and_decrypt(
    openssl: str,
    sm4_key_hex: Any,
    hmac_key_hex: Any,
    package: Any,
    *,
    crypt_fn: CryptFunction = sm4_runner.sm4_crypt,
    hmac_fn: HmacFunction = hmac_sm3_runner.hmac_sm3,
) -> bytes:
    """Authenticate all protected fields before decrypting with SM4-CTR."""
    sm4_key, hmac_key = validate_keys(sm4_key_hex, hmac_key_hex)
    normalized = validate_package(package)
    authenticated_data = package_authenticated_data(normalized)
    actual_tag = normalize_hex(
        hmac_fn(openssl, hmac_key, authenticated_data),
        "calculated tag",
        exact_bytes=TAG_BYTES,
    )
    if not hmac.compare_digest(actual_tag, normalized["tag"]):
        raise AuthenticationError("authentication failed")

    return crypt_fn(
        openssl,
        "CTR",
        "decrypt",
        sm4_key,
        normalized["iv"],
        bytes.fromhex(normalized["ciphertext"]),
    )
