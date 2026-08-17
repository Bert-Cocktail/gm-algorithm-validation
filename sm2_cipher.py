"""SM2 encryption helpers and ciphertext-format conversions."""

from __future__ import annotations

import base64
import hmac
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


SM2_FIELD = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
SM2_B = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
SM2_ORDER = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
SM2_C1_BYTES = 65
SM2_C3_BYTES = 32
SUPPORTED_FORMATS = {"der", "c1c3c2", "c1c2c3"}


class CipherError(ValueError):
    """Raised for invalid SM2 keys, ciphertexts, or backend failures."""


@dataclass(frozen=True)
class CiphertextParts:
    c1: bytes
    c2: bytes
    c3: bytes


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise CipherError("truncated DER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 4 or offset + 1 + count > len(data):
        raise CipherError("invalid DER length")
    encoded = data[offset + 1 : offset + 1 + count]
    if encoded[0] == 0:
        raise CipherError("non-canonical DER length")
    length = int.from_bytes(encoded, "big")
    if length < 0x80:
        raise CipherError("non-canonical DER length")
    return length, offset + 1 + count


def _read_tlv(data: bytes, offset: int, tag: int, name: str) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != tag:
        raise CipherError(f"SM2 DER ciphertext must contain {name}")
    length, start = _read_der_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise CipherError(f"truncated {name}")
    return data[start:end], end


def _decode_positive_integer(encoded: bytes, name: str) -> int:
    if not encoded:
        raise CipherError(f"empty {name}")
    if encoded[0] & 0x80:
        raise CipherError(f"{name} must be positive")
    if len(encoded) > 1 and encoded[0] == 0 and not (encoded[1] & 0x80):
        raise CipherError(f"non-canonical {name}")
    value = int.from_bytes(encoded, "big")
    if value >= SM2_FIELD:
        raise CipherError(f"{name} is outside the SM2 field")
    return value


def _encode_der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_der_length(len(content)) + content


def _encode_integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _encode_tlv(0x02, encoded)


def _validate_c1(c1: bytes, *, require_sm2_curve: bool = False) -> None:
    if len(c1) != SM2_C1_BYTES or c1[0] != 0x04:
        raise CipherError("C1 must be a 65-byte uncompressed point beginning with 04")
    x = int.from_bytes(c1[1:33], "big")
    y = int.from_bytes(c1[33:], "big")
    if x >= SM2_FIELD or y >= SM2_FIELD:
        raise CipherError("C1 coordinates are outside the 256-bit SM2 field")
    if require_sm2_curve and (y * y - (x * x * x + SM2_A * x + SM2_B)) % SM2_FIELD != 0:
        raise CipherError("C1 is not a point on the sm2p256v1 curve")


def parse_ciphertext(ciphertext: bytes, ciphertext_format: str) -> CiphertextParts:
    ciphertext_format = ciphertext_format.lower()
    if ciphertext_format not in SUPPORTED_FORMATS:
        raise CipherError(f"unsupported SM2 ciphertext format: {ciphertext_format}")
    if ciphertext_format == "der":
        if not ciphertext or ciphertext[0] != 0x30:
            raise CipherError("SM2 DER ciphertext must be a SEQUENCE")
        sequence_length, offset = _read_der_length(ciphertext, 1)
        if offset + sequence_length != len(ciphertext):
            raise CipherError("invalid SM2 DER ciphertext length")
        x_encoded, offset = _read_tlv(ciphertext, offset, 0x02, "x INTEGER")
        y_encoded, offset = _read_tlv(ciphertext, offset, 0x02, "y INTEGER")
        c3, offset = _read_tlv(ciphertext, offset, 0x04, "C3 OCTET STRING")
        c2, offset = _read_tlv(ciphertext, offset, 0x04, "C2 OCTET STRING")
        if offset != len(ciphertext):
            raise CipherError("unexpected data after SM2 DER ciphertext")
        x = _decode_positive_integer(x_encoded, "x INTEGER")
        y = _decode_positive_integer(y_encoded, "y INTEGER")
        c1 = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    else:
        if len(ciphertext) <= SM2_C1_BYTES + SM2_C3_BYTES:
            raise CipherError("SM2 ciphertext must contain non-empty C2 data")
        c1 = ciphertext[:SM2_C1_BYTES]
        if ciphertext_format == "c1c3c2":
            c3 = ciphertext[SM2_C1_BYTES : SM2_C1_BYTES + SM2_C3_BYTES]
            c2 = ciphertext[SM2_C1_BYTES + SM2_C3_BYTES :]
        else:
            c2 = ciphertext[SM2_C1_BYTES:-SM2_C3_BYTES]
            c3 = ciphertext[-SM2_C3_BYTES:]
    _validate_c1(c1)
    if len(c3) != SM2_C3_BYTES:
        raise CipherError("C3 must contain exactly 32 bytes")
    if not c2:
        raise CipherError("C2 must not be empty")
    return CiphertextParts(c1=c1, c2=c2, c3=c3)


def encode_ciphertext(parts: CiphertextParts, ciphertext_format: str) -> bytes:
    _validate_c1(parts.c1)
    if len(parts.c3) != SM2_C3_BYTES:
        raise CipherError("C3 must contain exactly 32 bytes")
    if not parts.c2:
        raise CipherError("C2 must not be empty")
    ciphertext_format = ciphertext_format.lower()
    if ciphertext_format == "c1c3c2":
        return parts.c1 + parts.c3 + parts.c2
    if ciphertext_format == "c1c2c3":
        return parts.c1 + parts.c2 + parts.c3
    if ciphertext_format == "der":
        x = int.from_bytes(parts.c1[1:33], "big")
        y = int.from_bytes(parts.c1[33:], "big")
        content = (
            _encode_integer(x)
            + _encode_integer(y)
            + _encode_tlv(0x04, parts.c3)
            + _encode_tlv(0x04, parts.c2)
        )
        return _encode_tlv(0x30, content)
    raise CipherError(f"unsupported SM2 ciphertext format: {ciphertext_format}")


def convert_ciphertext(ciphertext: bytes, source_format: str, target_format: str) -> bytes:
    return encode_ciphertext(parse_ciphertext(ciphertext, source_format), target_format)


def _pem(label: str, der: bytes) -> bytes:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[index : index + 64] for index in range(0, len(encoded), 64)]
    return (f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n").encode("ascii")


def public_key_pem(public_key: bytes) -> bytes:
    try:
        _validate_c1(public_key, require_sm2_curve=True)
    except CipherError as error:
        raise CipherError(f"invalid SM2 public key: {error}") from error
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a811ccf5501822d034200")
    return _pem("PUBLIC KEY", prefix + public_key)


def private_key_pem(private_key: bytes) -> bytes:
    if len(private_key) != 32:
        raise CipherError("SM2 private key must contain exactly 32 bytes")
    value = int.from_bytes(private_key, "big")
    if not 1 <= value < SM2_ORDER:
        raise CipherError("SM2 private key must be in the range [1, n-1]")
    content = (
        bytes.fromhex("0201010420")
        + private_key
        + bytes.fromhex("a00a06082a811ccf5501822d")
    )
    return _pem("EC PRIVATE KEY", _encode_tlv(0x30, content))


def _run_openssl(command: list[str], operation: str) -> bytes:
    try:
        process = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
    except OSError as error:
        raise CipherError(f"failed to run OpenSSL {operation}: {error}") from error
    if process.returncode != 0:
        detail = (process.stdout + process.stderr).decode("utf-8", errors="replace").strip()
        raise CipherError(f"OpenSSL SM2 {operation} failed: {detail or 'unknown error'}")
    return process.stdout


def openssl_encrypt(openssl: str, public_key: bytes, plaintext: bytes) -> bytes:
    if not plaintext:
        raise CipherError("SM2 plaintext must not be empty")
    with tempfile.TemporaryDirectory(prefix="sm2-encrypt-") as directory_name:
        directory = Path(directory_name)
        public_path = directory / "public.pem"
        plaintext_path = directory / "plaintext.bin"
        public_path.write_bytes(public_key_pem(public_key))
        plaintext_path.write_bytes(plaintext)
        return _run_openssl(
            [
                openssl,
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                str(public_path),
                "-in",
                str(plaintext_path),
            ],
            "encryption",
        )


def openssl_decrypt(openssl: str, private_key: bytes, ciphertext_der: bytes) -> bytes:
    parse_ciphertext(ciphertext_der, "der")
    with tempfile.TemporaryDirectory(prefix="sm2-decrypt-") as directory_name:
        directory = Path(directory_name)
        private_path = directory / "private.pem"
        ciphertext_path = directory / "ciphertext.der"
        private_path.write_bytes(private_key_pem(private_key))
        ciphertext_path.write_bytes(ciphertext_der)
        return _run_openssl(
            [
                openssl,
                "pkeyutl",
                "-decrypt",
                "-inkey",
                str(private_path),
                "-in",
                str(ciphertext_path),
            ],
            "decryption",
        )


def gmssl_encrypt(_openssl: str, public_key: bytes, plaintext: bytes) -> bytes:
    if not plaintext:
        raise CipherError("SM2 plaintext must not be empty")
    _validate_c1(public_key, require_sm2_curve=True)
    try:
        from gmssl import sm2
    except ImportError as error:
        raise CipherError("GmSSL backend requires 'gmssl==3.2.2'") from error
    crypt = sm2.CryptSM2(private_key="", public_key=public_key.hex(), mode=1)
    encrypted = crypt.encrypt(plaintext)
    if encrypted is None:
        raise CipherError("GmSSL SM2 encryption failed to derive a nonzero KDF")
    return b"\x04" + encrypted


def gmssl_decrypt(_openssl: str, private_key: bytes, ciphertext_c1c3c2: bytes) -> bytes:
    parts = parse_ciphertext(ciphertext_c1c3c2, "c1c3c2")
    _validate_c1(parts.c1, require_sm2_curve=True)
    try:
        from gmssl import func, sm2, sm3
    except ImportError as error:
        raise CipherError("GmSSL backend requires 'gmssl==3.2.2'") from error
    crypt = sm2.CryptSM2(private_key=private_key.hex(), public_key="", mode=1)
    shared = crypt._kg(int.from_bytes(private_key, "big"), parts.c1[1:].hex())
    if shared is None:
        raise CipherError("GmSSL SM2 decryption produced an invalid shared point")
    x2, y2 = shared[:64], shared[64:]
    mask = sm3.sm3_kdf(shared.encode("ascii"), len(parts.c2))
    if not mask or int(mask, 16) == 0:
        raise CipherError("GmSSL SM2 decryption derived an invalid KDF mask")
    plaintext = bytes(left ^ right for left, right in zip(parts.c2, bytes.fromhex(mask)))
    actual_c3 = bytes.fromhex(
        sm3.sm3_hash(func.bytes_to_list(bytes.fromhex(x2) + plaintext + bytes.fromhex(y2)))
    )
    if not hmac.compare_digest(actual_c3, parts.c3):
        raise CipherError("SM2 ciphertext integrity check failed")
    return plaintext
