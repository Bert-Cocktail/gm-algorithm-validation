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
    hmac_parser.add_argument(
        "--key-hex", required=True, help="HMAC key bytes in hexadecimal"
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
        raise UserInputError(f"unsupported command: {args.command}")
    except authenticated_sm4.AuthenticationError as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_VERIFY_FAILURE
    except (UserInputError, runner.RunnerError, hmac_sm3_runner.RunnerError) as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
