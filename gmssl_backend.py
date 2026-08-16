#!/usr/bin/env python3
"""Independent pure-Python GmSSL backend for cross-validation."""

from __future__ import annotations

from typing import Optional

from gmssl import sm3, sm4


SM3_BLOCK_BYTES = 64
SM4_BLOCK_BYTES = 16
SM4_MODES = {"ECB", "CBC", "CTR"}
SM4_DIRECTIONS = {"encrypt", "decrypt"}


class BackendError(ValueError):
    """Raised when the cross-validation backend receives invalid input."""


def gmssl_sm3(message: bytes) -> str:
    if not isinstance(message, bytes):
        raise BackendError("message must be bytes")
    return sm3.sm3_hash(list(message))


def gmssl_hmac_sm3(key: bytes, message: bytes) -> str:
    if not isinstance(key, bytes) or not isinstance(message, bytes):
        raise BackendError("key and message must be bytes")

    normalized_key = key
    if len(normalized_key) > SM3_BLOCK_BYTES:
        normalized_key = bytes.fromhex(gmssl_sm3(normalized_key))
    normalized_key = normalized_key.ljust(SM3_BLOCK_BYTES, b"\x00")
    inner_key = bytes(value ^ 0x36 for value in normalized_key)
    outer_key = bytes(value ^ 0x5C for value in normalized_key)
    inner_digest = bytes.fromhex(gmssl_sm3(inner_key + message))
    return gmssl_sm3(outer_key + inner_digest)


def gmssl_sm4_block(key: bytes, block: bytes, direction: str) -> bytes:
    if not isinstance(key, bytes) or len(key) != SM4_BLOCK_BYTES:
        raise BackendError("SM4 key must contain exactly 16 bytes")
    if not isinstance(block, bytes) or len(block) != SM4_BLOCK_BYTES:
        raise BackendError("SM4 block must contain exactly 16 bytes")
    if direction not in SM4_DIRECTIONS:
        raise BackendError("direction must be 'encrypt' or 'decrypt'")

    cipher = sm4.CryptSM4()
    mode = sm4.SM4_ENCRYPT if direction == "encrypt" else sm4.SM4_DECRYPT
    cipher.set_key(key, mode)
    return bytes(cipher.one_round(cipher.sk, list(block)))


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def gmssl_sm4_crypt(
    mode: str,
    direction: str,
    key: bytes,
    iv: Optional[bytes],
    data: bytes,
) -> bytes:
    mode = mode.upper()
    direction = direction.lower()
    if mode not in SM4_MODES:
        raise BackendError(f"unsupported SM4 mode: {mode}")
    if direction not in SM4_DIRECTIONS:
        raise BackendError("direction must be 'encrypt' or 'decrypt'")
    if not isinstance(key, bytes) or len(key) != SM4_BLOCK_BYTES:
        raise BackendError("SM4 key must contain exactly 16 bytes")
    if not isinstance(data, bytes):
        raise BackendError("data must be bytes")
    if mode == "ECB":
        if iv is not None:
            raise BackendError("ECB mode must not include an IV")
    elif not isinstance(iv, bytes) or len(iv) != SM4_BLOCK_BYTES:
        raise BackendError(f"{mode} IV must contain exactly 16 bytes")

    if mode in {"ECB", "CBC"} and (
        not data or len(data) % SM4_BLOCK_BYTES != 0
    ):
        raise BackendError(
            f"{mode} data must contain a non-empty whole number of 16-byte blocks"
        )

    if mode == "CTR":
        assert iv is not None
        counter = int.from_bytes(iv, "big")
        output = bytearray()
        for offset in range(0, len(data), SM4_BLOCK_BYTES):
            chunk = data[offset : offset + SM4_BLOCK_BYTES]
            counter_block = counter.to_bytes(SM4_BLOCK_BYTES, "big")
            stream = gmssl_sm4_block(key, counter_block, "encrypt")
            output.extend(_xor(chunk, stream[: len(chunk)]))
            counter = (counter + 1) % (1 << 128)
        return bytes(output)

    output = bytearray()
    previous = iv
    for offset in range(0, len(data), SM4_BLOCK_BYTES):
        block = data[offset : offset + SM4_BLOCK_BYTES]
        if mode == "ECB":
            result = gmssl_sm4_block(key, block, direction)
        elif direction == "encrypt":
            assert previous is not None
            result = gmssl_sm4_block(key, _xor(block, previous), "encrypt")
            previous = result
        else:
            assert previous is not None
            result = _xor(gmssl_sm4_block(key, block, "decrypt"), previous)
            previous = block
        output.extend(result)
    return bytes(output)
