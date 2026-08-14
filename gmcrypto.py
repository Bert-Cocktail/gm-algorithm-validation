#!/usr/bin/env python3
"""User-facing command-line tools for supported GM algorithms."""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

import runner


EXIT_SUCCESS = 0
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
    return parser.parse_args(argv)


def decode_hex_message(value: str) -> bytes:
    if len(value) % 2 != 0:
        raise UserInputError("--hex must contain whole bytes (an even number of characters)")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise UserInputError("--hex contains non-hexadecimal characters") from error


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
        raise UserInputError(f"unsupported command: {args.command}")
    except (UserInputError, runner.RunnerError) as error:
        print(f"Error: {error}", file=error_output)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
