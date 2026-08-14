#!/usr/bin/env python3
"""User-facing command-line tools for supported GM algorithms."""

from __future__ import annotations

import argparse
import hmac
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import runner
import hmac_sm3_runner


EXIT_SUCCESS = 0
EXIT_VERIFY_FAILURE = 1
EXIT_INPUT_ERROR = 2


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
        raise UserInputError(f"unsupported command: {args.command}")
    except (UserInputError, runner.RunnerError, hmac_sm3_runner.RunnerError) as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
