#!/usr/bin/env python3
"""User-facing command-line tools for supported GM algorithms."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import runner
import authenticated_sm4
import hmac_sm3_runner
import sm2_runner
import sm2_cipher


EXIT_SUCCESS = 0
EXIT_VERIFY_FAILURE = 1
EXIT_INPUT_ERROR = 2
MAX_FILE_BYTES = 64 * 1024 * 1024


class UserInputError(Exception):
    """Raised when a user-facing command receives invalid input."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Calculate digests and perform supported GM crypto operations."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    sm3_parser = commands.add_parser("sm3", help="calculate an SM3 digest")
    source = sm3_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text", help="text to encode and hash")
    source.add_argument("--hex", dest="hex_message", help="message bytes in hexadecimal")
    source.add_argument("--file", type=Path, help="file whose bytes will be hashed")
    sm3_parser.add_argument(
        "--encoding",
        default="utf-8",
        help="encoding used with --text (default: utf-8)",
    )
    sm3_parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )

    hmac_parser = commands.add_parser(
        "hmac-sm3", help="calculate or verify an HMAC-SM3 tag"
    )
    hmac_source = hmac_parser.add_mutually_exclusive_group(required=True)
    hmac_source.add_argument("--text", help="text to encode and authenticate")
    hmac_source.add_argument(
        "--hex", dest="hex_message", help="message bytes in hexadecimal"
    )
    hmac_source.add_argument(
        "--file", type=Path, help="file whose bytes will be authenticated"
    )
    hmac_key = hmac_parser.add_mutually_exclusive_group(required=True)
    hmac_key.add_argument(
        "--key-file", type=Path, help="file containing the raw HMAC key bytes"
    )
    hmac_key.add_argument(
        "--key-hex", help="legacy HMAC key input in hexadecimal"
    )
    hmac_parser.add_argument(
        "--verify",
        metavar="TAG",
        help="verify this 32-byte hexadecimal tag instead of printing a new tag",
    )
    hmac_parser.add_argument(
        "--encoding",
        default="utf-8",
        help="encoding used with --text (default: utf-8)",
    )
    hmac_parser.add_argument(
        "--openssl",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )

    keygen_parser = commands.add_parser(
        "generate-auth-key", help="generate an SM4/HMAC key file"
    )
    keygen_parser.add_argument("--output", type=Path, required=True)
    keygen_parser.add_argument(
        "--force", action="store_true", help="replace an existing output file"
    )

    hmac_keygen_parser = commands.add_parser(
        "generate-hmac-key", help="generate a raw binary HMAC key file"
    )
    hmac_keygen_parser.add_argument("--output", type=Path, required=True)
    hmac_keygen_parser.add_argument(
        "--bytes", type=int, default=32, help="key length in bytes (default: 32)"
    )
    hmac_keygen_parser.add_argument(
        "--force", action="store_true", help="replace an existing output file"
    )

    encrypt_parser = commands.add_parser(
        "encrypt-auth", help="encrypt and authenticate data"
    )
    encrypt_source = encrypt_parser.add_mutually_exclusive_group(required=True)
    encrypt_source.add_argument("--text", help="text to encode and encrypt")
    encrypt_source.add_argument(
        "--hex", dest="hex_message", help="plaintext bytes in hexadecimal"
    )
    encrypt_source.add_argument("--file", type=Path, help="plaintext input file")
    encrypt_parser.add_argument("--key-file", type=Path, required=True)
    encrypt_parser.add_argument("--output", type=Path, required=True)
    encrypt_parser.add_argument("--encoding", default="utf-8")
    encrypt_parser.add_argument("--force", action="store_true")
    encrypt_parser.add_argument("--openssl", default="openssl")

    decrypt_parser = commands.add_parser(
        "decrypt-auth", help="authenticate and decrypt a package"
    )
    decrypt_parser.add_argument("--package", type=Path, required=True)
    decrypt_parser.add_argument("--key-file", type=Path, required=True)
    decrypt_parser.add_argument("--output", type=Path, required=True)
    decrypt_parser.add_argument("--force", action="store_true")
    decrypt_parser.add_argument("--openssl", default="openssl")

    sm2_keygen_parser = commands.add_parser(
        "sm2-keygen", help="generate an SM2 PEM private/public key pair"
    )
    sm2_keygen_parser.add_argument("--private-key", type=Path, required=True)
    sm2_keygen_parser.add_argument("--public-key", type=Path, required=True)
    sm2_keygen_parser.add_argument("--force", action="store_true")
    sm2_keygen_parser.add_argument("--openssl", default="openssl")

    sm2_sign_parser = commands.add_parser(
        "sm2-sign", help="sign a file with an SM2 PEM private key"
    )
    sm2_sign_parser.add_argument("--private-key", type=Path, required=True)
    sm2_sign_parser.add_argument("--input", type=Path, required=True)
    sm2_sign_parser.add_argument("--signature", type=Path, required=True)
    sm2_sign_parser.add_argument(
        "--user-id", default="1234567812345678", help="SM2 signer ID"
    )
    sm2_sign_parser.add_argument("--force", action="store_true")
    sm2_sign_parser.add_argument("--openssl", default="openssl")

    sm2_verify_parser = commands.add_parser(
        "sm2-verify", help="verify an SM2 DER signature for a file"
    )
    sm2_verify_parser.add_argument("--public-key", type=Path, required=True)
    sm2_verify_parser.add_argument("--input", type=Path, required=True)
    sm2_verify_parser.add_argument("--signature", type=Path, required=True)
    sm2_verify_parser.add_argument(
        "--user-id", default="1234567812345678", help="SM2 signer ID"
    )
    sm2_verify_parser.add_argument("--openssl", default="openssl")

    sm2_encrypt_parser = commands.add_parser(
        "sm2-encrypt", help="encrypt a file with an SM2 PEM public key"
    )
    sm2_encrypt_parser.add_argument("--public-key", type=Path, required=True)
    sm2_encrypt_parser.add_argument("--input", type=Path, required=True)
    sm2_encrypt_parser.add_argument("--output", type=Path, required=True)
    sm2_encrypt_parser.add_argument(
        "--format", choices=sorted(sm2_cipher.SUPPORTED_FORMATS), default="der"
    )
    sm2_encrypt_parser.add_argument("--force", action="store_true")
    sm2_encrypt_parser.add_argument("--openssl", default="openssl")

    sm2_decrypt_parser = commands.add_parser(
        "sm2-decrypt", help="decrypt an SM2 ciphertext with a PEM private key"
    )
    sm2_decrypt_parser.add_argument("--private-key", type=Path, required=True)
    sm2_decrypt_parser.add_argument("--input", type=Path, required=True)
    sm2_decrypt_parser.add_argument("--output", type=Path, required=True)
    sm2_decrypt_parser.add_argument(
        "--format", choices=sorted(sm2_cipher.SUPPORTED_FORMATS), default="der"
    )
    sm2_decrypt_parser.add_argument("--force", action="store_true")
    sm2_decrypt_parser.add_argument("--openssl", default="openssl")

    sm2_convert_parser = commands.add_parser(
        "sm2-convert", help="convert an SM2 ciphertext between DER, C1C3C2, and C1C2C3"
    )
    sm2_convert_parser.add_argument("--input", type=Path, required=True)
    sm2_convert_parser.add_argument("--output", type=Path, required=True)
    sm2_convert_parser.add_argument(
        "--from-format", choices=sorted(sm2_cipher.SUPPORTED_FORMATS), required=True
    )
    sm2_convert_parser.add_argument(
        "--to-format", choices=sorted(sm2_cipher.SUPPORTED_FORMATS), required=True
    )
    sm2_convert_parser.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def decode_hex_message(value: str) -> bytes:
    if len(value) % 2 != 0:
        raise UserInputError("--hex must contain whole bytes (an even number of characters)")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise UserInputError("--hex contains non-hexadecimal characters") from error


def normalize_hex(value: str, option: str, *, expected_bytes: int | None = None) -> str:
    if len(value) % 2 != 0:
        raise UserInputError(f"{option} must contain whole bytes")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise UserInputError(f"{option} contains non-hexadecimal characters") from error
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        raise UserInputError(
            f"{option} must contain exactly {expected_bytes} bytes "
            f"({expected_bytes * 2} hexadecimal characters)"
        )
    return value.lower()


def encode_text(value: str, encoding: str) -> bytes:
    try:
        return value.encode(encoding)
    except LookupError as error:
        raise UserInputError(f"unknown text encoding: {encoding}") from error
    except UnicodeEncodeError as error:
        raise UserInputError(
            f"the text cannot be represented with encoding '{encoding}'"
        ) from error


def sm3_file_digest(openssl: str, path: Path) -> str:
    if not path.exists():
        raise UserInputError(f"file not found: {path}")
    if not path.is_file():
        raise UserInputError(f"path is not a regular file: {path}")

    try:
        process = subprocess.run(
            [openssl, "dgst", "-sm3", "-binary", str(path.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise UserInputError(f"failed to read or hash file: {error}") from error

    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", errors="replace").strip()
        raise UserInputError(f"OpenSSL SM3 failed: {detail or 'unknown error'}")
    if len(process.stdout) != 32:
        raise UserInputError(
            f"OpenSSL returned {len(process.stdout)} bytes; an SM3 digest must be 32 bytes"
        )
    return process.stdout.hex()


def run_sm3(args: argparse.Namespace, openssl: str) -> str:
    if args.file is not None:
        if args.encoding != "utf-8":
            raise UserInputError("--encoding can only be used together with --text")
        return sm3_file_digest(openssl, args.file)

    if args.hex_message is not None:
        if args.encoding != "utf-8":
            raise UserInputError("--encoding can only be used together with --text")
        message = decode_hex_message(args.hex_message)
    else:
        message = encode_text(args.text, args.encoding)
    return runner.sm3_digest(openssl, message)


def message_bytes_from_args(args: argparse.Namespace) -> bytes:
    if args.hex_message is not None:
        if args.encoding != "utf-8":
            raise UserInputError("--encoding can only be used together with --text")
        return decode_hex_message(args.hex_message)
    if args.text is not None:
        return encode_text(args.text, args.encoding)
    raise UserInputError("this operation requires text or hexadecimal message input")


def read_limited_file(path: Path, description: str) -> bytes:
    if not path.exists():
        raise UserInputError(f"{description} not found: {path}")
    if not path.is_file():
        raise UserInputError(f"{description} is not a regular file: {path}")
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise UserInputError(
                f"{description} exceeds the {MAX_FILE_BYTES // (1024 * 1024)} MiB limit"
            )
        return path.read_bytes()
    except OSError as error:
        raise UserInputError(f"failed to read {description}: {error}") from error


def load_json_object(path: Path, description: str) -> dict[str, object]:
    raw = read_limited_file(path, description)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UserInputError(f"{description} must be valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise UserInputError(f"{description} must contain a JSON object")
    return value


def load_auth_keys(path: Path) -> tuple[str, str]:
    document = load_json_object(path, "key file")
    if set(document) != {"sm4Key", "hmacKey"}:
        raise UserInputError(
            "key file must contain exactly the 'sm4Key' and 'hmacKey' fields"
        )
    try:
        return authenticated_sm4.validate_keys(
            document["sm4Key"], document["hmacKey"]
        )
    except authenticated_sm4.FormatError as error:
        raise UserInputError(f"invalid key file: {error}") from error


def write_atomic(path: Path, data: bytes, *, force: bool) -> None:
    parent = path.parent
    if not parent.exists() or not parent.is_dir():
        raise UserInputError(f"output directory not found: {parent}")
    if path.exists() and not force:
        raise UserInputError(f"output file already exists: {path} (use --force to replace it)")

    temporary: Path | None = None
    reserved_output = False
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(data)
            output_file.flush()
            os.fsync(output_file.fileno())
        if not force:
            reservation = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(reservation)
            reserved_output = True
        os.replace(temporary, path)
        temporary = None
        reserved_output = False
    except FileExistsError as error:
        raise UserInputError(
            f"output file already exists: {path} (use --force to replace it)"
        ) from error
    except OSError as error:
        raise UserInputError(f"failed to write output file: {error}") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if reserved_output:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def run_generate_auth_key(args: argparse.Namespace) -> None:
    document = {
        "sm4Key": secrets.token_hex(authenticated_sm4.SM4_KEY_BYTES),
        "hmacKey": secrets.token_hex(authenticated_sm4.HMAC_KEY_BYTES),
    }
    encoded = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    write_atomic(args.output, encoded, force=args.force)


def run_generate_hmac_key(args: argparse.Namespace) -> None:
    if args.bytes < 1 or args.bytes > 4096:
        raise UserInputError("--bytes must be between 1 and 4096")
    write_atomic(args.output, secrets.token_bytes(args.bytes), force=args.force)


def run_encrypt_auth(args: argparse.Namespace, openssl: str) -> None:
    sm4_key, hmac_key = load_auth_keys(args.key_file)
    if args.file is not None:
        if args.encoding != "utf-8":
            raise UserInputError("--encoding can only be used together with --text")
        plaintext = read_limited_file(args.file, "plaintext file")
    else:
        plaintext = message_bytes_from_args(args)
    package = authenticated_sm4.encrypt_and_authenticate(
        openssl, sm4_key, hmac_key, plaintext
    )
    encoded = (json.dumps(package, indent=2) + "\n").encode("utf-8")
    write_atomic(args.output, encoded, force=args.force)


def run_decrypt_auth(args: argparse.Namespace, openssl: str) -> None:
    sm4_key, hmac_key = load_auth_keys(args.key_file)
    package = load_json_object(args.package, "authenticated package")
    try:
        plaintext = authenticated_sm4.verify_and_decrypt(
            openssl, sm4_key, hmac_key, package
        )
    except authenticated_sm4.FormatError as error:
        raise UserInputError(f"invalid authenticated package: {error}") from error
    write_atomic(args.output, plaintext, force=args.force)


def run_hmac_sm3(args: argparse.Namespace, openssl: str) -> tuple[str, bool | None]:
    if args.key_file is not None:
        key = read_limited_file(args.key_file, "HMAC key file")
        if not key:
            raise UserInputError("HMAC key file must not be empty")
        key_hex = key.hex()
    else:
        key_hex = normalize_hex(args.key_hex, "--key-hex")
        if not key_hex:
            raise UserInputError("--key-hex must not be empty")

    if args.file is not None:
        if args.encoding != "utf-8":
            raise UserInputError("--encoding can only be used together with --text")
        if not args.file.exists():
            raise UserInputError(f"file not found: {args.file}")
        if not args.file.is_file():
            raise UserInputError(f"path is not a regular file: {args.file}")
        try:
            message = args.file.read_bytes()
        except OSError as error:
            raise UserInputError(f"failed to read file: {error}") from error
        actual = hmac_sm3_runner.hmac_sm3(openssl, key_hex, message)
    else:
        actual = hmac_sm3_runner.hmac_sm3(
            openssl, key_hex, message_bytes_from_args(args)
        )

    if args.verify is None:
        return actual, None

    expected = normalize_hex(args.verify, "--verify", expected_bytes=32)
    return actual, hmac.compare_digest(actual, expected)


def validate_sm2_user_id(value: str) -> str:
    encoded = value.encode("utf-8")
    if not encoded:
        raise UserInputError("--user-id must not be empty")
    if len(encoded) > 8191:
        raise UserInputError("--user-id is too long for the SM2 ENTL field")
    if "\x00" in value:
        raise UserInputError("--user-id must not contain NUL characters")
    return value


def run_openssl_command(command: list[str], operation: str) -> subprocess.CompletedProcess[bytes]:
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as error:
        raise UserInputError(f"failed to run OpenSSL {operation}: {error}") from error
    return process


def require_openssl_success(
    process: subprocess.CompletedProcess[bytes], operation: str
) -> None:
    if process.returncode != 0:
        detail = (process.stdout + process.stderr).decode(
            "utf-8", errors="replace"
        ).strip()
        raise UserInputError(f"OpenSSL {operation} failed: {detail or 'unknown error'}")


def run_sm2_keygen(args: argparse.Namespace, openssl: str) -> None:
    if args.private_key.resolve() == args.public_key.resolve():
        raise UserInputError("private and public key paths must be different")
    for path in (args.private_key, args.public_key):
        if not path.parent.exists() or not path.parent.is_dir():
            raise UserInputError(f"output directory not found: {path.parent}")
        if path.exists() and not args.force:
            raise UserInputError(
                f"output file already exists: {path} (use --force to replace it)"
            )

    with tempfile.TemporaryDirectory(prefix="sm2-keygen-") as directory_name:
        directory = Path(directory_name)
        private_temp = directory / "private.pem"
        public_temp = directory / "public.pem"
        message_temp = directory / "self-test-message.bin"
        signature_temp = directory / "self-test-signature.der"
        require_openssl_success(
            run_openssl_command(
                [
                    openssl,
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:SM2",
                    "-out",
                    str(private_temp),
                ],
                "SM2 key generation",
            ),
            "SM2 key generation",
        )
        require_openssl_success(
            run_openssl_command(
                [
                    openssl,
                    "pkey",
                    "-in",
                    str(private_temp),
                    "-pubout",
                    "-out",
                    str(public_temp),
                ],
                "SM2 public-key export",
            ),
            "SM2 public-key export",
        )
        message_temp.write_bytes(b"")
        require_openssl_success(
            run_openssl_command(
                [
                    openssl,
                    "dgst",
                    "-sm3",
                    "-sign",
                    str(private_temp),
                    "-sigopt",
                    "distid:1234567812345678",
                    "-out",
                    str(signature_temp),
                    str(message_temp),
                ],
                "SM2 key self-test",
            ),
            "SM2 key self-test",
        )
        require_openssl_success(
            run_openssl_command(
                [
                    openssl,
                    "dgst",
                    "-sm3",
                    "-verify",
                    str(public_temp),
                    "-signature",
                    str(signature_temp),
                    "-sigopt",
                    "distid:1234567812345678",
                    str(message_temp),
                ],
                "SM2 key self-test verification",
            ),
            "SM2 key self-test verification",
        )
        write_atomic(
            args.private_key, private_temp.read_bytes(), force=args.force
        )
        write_atomic(args.public_key, public_temp.read_bytes(), force=args.force)


def run_sm2_sign(args: argparse.Namespace, openssl: str) -> None:
    validate_sm2_user_id(args.user_id)
    read_limited_file(args.private_key, "SM2 private key")
    read_limited_file(args.input, "input file")
    with tempfile.TemporaryDirectory(prefix="sm2-sign-") as directory_name:
        signature_temp = Path(directory_name) / "signature.der"
        process = run_openssl_command(
            [
                openssl,
                "dgst",
                "-sm3",
                "-sign",
                str(args.private_key.resolve()),
                "-sigopt",
                f"distid:{args.user_id}",
                "-out",
                str(signature_temp),
                str(args.input.resolve()),
            ],
            "SM2 signing",
        )
        require_openssl_success(process, "SM2 signing")
        signature = signature_temp.read_bytes()
    try:
        sm2_runner.der_signature_to_raw(signature)
    except sm2_runner.RunnerError as error:
        raise UserInputError(f"OpenSSL returned an invalid SM2 signature: {error}") from error
    write_atomic(args.signature, signature, force=args.force)


def run_sm2_verify(args: argparse.Namespace, openssl: str) -> bool:
    validate_sm2_user_id(args.user_id)
    read_limited_file(args.public_key, "SM2 public key")
    read_limited_file(args.input, "input file")
    signature = read_limited_file(args.signature, "SM2 signature")
    try:
        sm2_runner.der_signature_to_raw(signature)
    except sm2_runner.RunnerError as error:
        raise UserInputError(f"invalid SM2 DER signature: {error}") from error
    process = run_openssl_command(
        [
            openssl,
            "dgst",
            "-sm3",
            "-verify",
            str(args.public_key.resolve()),
            "-signature",
            str(args.signature.resolve()),
            "-sigopt",
            f"distid:{args.user_id}",
            str(args.input.resolve()),
        ],
        "SM2 verification",
    )
    output = (process.stdout + process.stderr).decode("utf-8", errors="replace")
    if process.returncode == 0:
        return True
    if process.returncode == 1 and "verification failure" in output.lower():
        return False
    raise UserInputError(
        f"OpenSSL SM2 verification failed: {output.strip() or 'unknown error'}"
    )


def run_sm2_encrypt(args: argparse.Namespace, openssl: str) -> None:
    read_limited_file(args.public_key, "SM2 public key")
    plaintext = read_limited_file(args.input, "plaintext file")
    if not plaintext:
        raise UserInputError("SM2 plaintext file must not be empty")
    process = run_openssl_command(
        [openssl, "pkeyutl", "-encrypt", "-pubin", "-inkey", str(args.public_key.resolve()),
         "-in", str(args.input.resolve())],
        "SM2 encryption",
    )
    require_openssl_success(process, "SM2 encryption")
    try:
        ciphertext = sm2_cipher.convert_ciphertext(process.stdout, "der", args.format)
    except sm2_cipher.CipherError as error:
        raise UserInputError(f"OpenSSL returned an invalid SM2 ciphertext: {error}") from error
    write_atomic(args.output, ciphertext, force=args.force)


def run_sm2_decrypt(args: argparse.Namespace, openssl: str) -> None:
    read_limited_file(args.private_key, "SM2 private key")
    ciphertext = read_limited_file(args.input, "SM2 ciphertext")
    try:
        ciphertext_der = sm2_cipher.convert_ciphertext(ciphertext, args.format, "der")
    except sm2_cipher.CipherError as error:
        raise UserInputError(f"invalid SM2 ciphertext: {error}") from error
    with tempfile.TemporaryDirectory(prefix="sm2-decrypt-") as directory_name:
        ciphertext_path = Path(directory_name) / "ciphertext.der"
        ciphertext_path.write_bytes(ciphertext_der)
        process = run_openssl_command(
            [openssl, "pkeyutl", "-decrypt", "-inkey", str(args.private_key.resolve()),
             "-in", str(ciphertext_path)],
            "SM2 decryption",
        )
    require_openssl_success(process, "SM2 decryption")
    write_atomic(args.output, process.stdout, force=args.force)


def run_sm2_convert(args: argparse.Namespace) -> None:
    ciphertext = read_limited_file(args.input, "SM2 ciphertext")
    try:
        converted = sm2_cipher.convert_ciphertext(
            ciphertext, args.from_format, args.to_format
        )
    except sm2_cipher.CipherError as error:
        raise UserInputError(f"invalid SM2 ciphertext: {error}") from error
    write_atomic(args.output, converted, force=args.force)


def main(
    argv: Sequence[str] | None = None,
    *,
    output: TextIO = sys.stdout,
    error_output: TextIO = sys.stderr,
) -> int:
    args = parse_args(argv)
    try:
        if args.command == "generate-auth-key":
            run_generate_auth_key(args)
            print(args.output, file=output)
            return EXIT_SUCCESS
        if args.command == "generate-hmac-key":
            run_generate_hmac_key(args)
            print(args.output, file=output)
            return EXIT_SUCCESS
        if args.command == "sm2-keygen":
            openssl = runner.resolve_openssl(args.openssl)
            run_sm2_keygen(args, openssl)
            print(args.private_key, file=output)
            print(args.public_key, file=output)
            return EXIT_SUCCESS
        if args.command == "sm2-convert":
            run_sm2_convert(args)
            print(args.output, file=output)
            return EXIT_SUCCESS
        openssl = runner.resolve_openssl(args.openssl)
        if args.command == "sm3":
            print(run_sm3(args, openssl), file=output)
            return EXIT_SUCCESS
        if args.command == "hmac-sm3":
            tag, verified = run_hmac_sm3(args, openssl)
            if verified is None:
                print(tag, file=output)
                return EXIT_SUCCESS
            print("OK" if verified else "FAIL", file=output)
            return EXIT_SUCCESS if verified else EXIT_VERIFY_FAILURE
        if args.command == "encrypt-auth":
            run_encrypt_auth(args, openssl)
            print(args.output, file=output)
            return EXIT_SUCCESS
        if args.command == "decrypt-auth":
            run_decrypt_auth(args, openssl)
            print(args.output, file=output)
            return EXIT_SUCCESS
        if args.command == "sm2-sign":
            run_sm2_sign(args, openssl)
            print(args.signature, file=output)
            return EXIT_SUCCESS
        if args.command == "sm2-verify":
            verified = run_sm2_verify(args, openssl)
            print("OK" if verified else "FAIL", file=output)
            return EXIT_SUCCESS if verified else EXIT_VERIFY_FAILURE
        if args.command == "sm2-encrypt":
            run_sm2_encrypt(args, openssl)
            print(args.output, file=output)
            return EXIT_SUCCESS
        if args.command == "sm2-decrypt":
            run_sm2_decrypt(args, openssl)
            print(args.output, file=output)
            return EXIT_SUCCESS
        raise UserInputError(f"unsupported command: {args.command}")
    except authenticated_sm4.AuthenticationError as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_VERIFY_FAILURE
    except (
        UserInputError,
        runner.RunnerError,
        hmac_sm3_runner.RunnerError,
        sm2_runner.RunnerError,
        sm2_cipher.CipherError,
    ) as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
