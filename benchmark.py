#!/usr/bin/env python3
"""Measure local SM2/SM3/SM4 operation performance and write reproducible reports."""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import hmac_sm3_runner
import runner
import sm2_cipher
import sm4_runner


PRIVATE_KEY = (1).to_bytes(32, "big")
PUBLIC_KEY = bytes.fromhex(
    "0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
)
SM4_KEY = "0123456789abcdeffedcba9876543210"
SM4_IV = "000102030405060708090a0b0c0d0e0f"
HMAC_KEY = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"


class BenchmarkError(ValueError):
    """Raised for invalid benchmark arguments or output paths."""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark local national-crypto backends.")
    parser.add_argument("--backend", choices=("openssl", "gmssl", "both"), default="both")
    parser.add_argument("--sizes", default="16,1024,65536", help="comma-separated byte sizes")
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--quick", action="store_true", help="use 16/1024 bytes and 2 timed runs")
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--json", type=Path, default=Path("results/benchmark.json"))
    parser.add_argument("--markdown", type=Path, default=Path("reports/benchmark.md"))
    return parser.parse_args(argv)


def _sizes(value: str) -> list[int]:
    try:
        sizes = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise BenchmarkError("--sizes must contain comma-separated integers") from error
    if not sizes or any(size <= 0 for size in sizes):
        raise BenchmarkError("benchmark sizes must be positive")
    return sizes


def _measure(function: Callable[[], Any], iterations: int, warmup: int) -> list[int]:
    for _ in range(warmup):
        function()
    samples = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        function()
        samples.append(time.perf_counter_ns() - started)
    return samples


def _result(
    backend: str, operation: str, size: int, samples: list[int]
) -> dict[str, Any]:
    mean_ns = statistics.fmean(samples)
    median_ns = statistics.median(samples)
    seconds = mean_ns / 1_000_000_000
    return {
        "backend": backend,
        "operation": operation,
        "messageBytes": size,
        "status": "measured",
        "iterations": len(samples),
        "meanMs": round(mean_ns / 1_000_000, 6),
        "medianMs": round(median_ns / 1_000_000, 6),
        "operationsPerSecond": round(1 / seconds, 3),
        "throughputMiBPerSecond": round(size / seconds / (1024 * 1024), 3),
    }


def _unavailable(backend: str, operation: str, size: int, error: Exception) -> dict[str, Any]:
    detail = str(error).splitlines()[0][:200] or type(error).__name__
    return {
        "backend": backend,
        "operation": operation,
        "messageBytes": size,
        "status": "skipped",
        "reason": detail,
    }


def _operation(backend: str, operation: str, data: bytes, openssl: str) -> Callable[[], Any]:
    if operation == "SM3":
        return (
            (lambda: runner.sm3_digest(openssl, data))
            if backend == "openssl"
            else (lambda: runner._load_gmssl_backend().gmssl_sm3(data))
        )
    if operation == "HMAC-SM3":
        return (
            (lambda: hmac_sm3_runner.hmac_sm3(openssl, HMAC_KEY, data))
            if backend == "openssl"
            else (lambda: runner._load_gmssl_backend().gmssl_hmac_sm3(bytes.fromhex(HMAC_KEY), data))
        )
    if operation == "SM4-CTR-encrypt":
        return (
            (lambda: sm4_runner.sm4_crypt(openssl, "CTR", "encrypt", SM4_KEY, SM4_IV, data))
            if backend == "openssl"
            else (lambda: runner._load_gmssl_backend().gmssl_sm4_crypt(
                "CTR", "encrypt", bytes.fromhex(SM4_KEY), bytes.fromhex(SM4_IV), data
            ))
        )
    if operation == "SM2-encrypt":
        return (
            (lambda: sm2_cipher.openssl_encrypt(openssl, PUBLIC_KEY, data))
            if backend == "openssl"
            else (lambda: sm2_cipher.gmssl_encrypt("", PUBLIC_KEY, data))
        )
    if operation == "SM2-decrypt":
        if backend == "openssl":
            ciphertext = sm2_cipher.openssl_encrypt(openssl, PUBLIC_KEY, data)
            return lambda: sm2_cipher.openssl_decrypt(openssl, PRIVATE_KEY, ciphertext)
        ciphertext = sm2_cipher.gmssl_encrypt("", PUBLIC_KEY, data)
        return lambda: sm2_cipher.gmssl_decrypt("", PRIVATE_KEY, ciphertext)
    raise BenchmarkError(f"unsupported benchmark operation: {operation}")


def run_suite(
    backends: list[str], sizes: list[int], iterations: int, warmup: int, openssl: str
) -> list[dict[str, Any]]:
    if iterations <= 0 or warmup < 0:
        raise BenchmarkError("iterations must be positive and warmup must not be negative")
    results: list[dict[str, Any]] = []
    for backend in backends:
        for size in sizes:
            data = bytes(index % 251 for index in range(size))
            for operation in ("SM3", "HMAC-SM3", "SM4-CTR-encrypt"):
                try:
                    function = _operation(backend, operation, data, openssl)
                    results.append(_result(backend, operation, size, _measure(function, iterations, warmup)))
                except Exception as error:
                    results.append(_unavailable(backend, operation, size, error))
        sm2_data = bytes(range(32))
        for operation in ("SM2-encrypt", "SM2-decrypt"):
            try:
                function = _operation(backend, operation, sm2_data, openssl)
                results.append(_result(backend, operation, len(sm2_data), _measure(function, iterations, warmup)))
            except Exception as error:
                results.append(_unavailable(backend, operation, len(sm2_data), error))
    return results


def build_report(backends: list[str], sizes: list[int], iterations: int, warmup: int, openssl: str) -> dict[str, Any]:
    version = "not selected"
    if "openssl" in backends:
        process = subprocess.run([openssl, "version"], capture_output=True, text=True, check=False)
        version = (process.stdout or process.stderr).strip()
    measurements = run_suite(backends, sizes, iterations, warmup, openssl)
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "openssl": version,
        },
        "configuration": {
            "backends": backends,
            "messageSizes": sizes,
            "iterations": iterations,
            "warmup": warmup,
        },
        "measurements": measurements,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Cryptographic Performance Report", "",
        f"Generated: `{report['generatedAt']}`", "",
        "Results are local measurements, not certification or cross-machine performance guarantees.", "",
        "| Backend | Operation | Bytes | Status | Median ms | Ops/s | MiB/s |",
        "|---|---|---:|---|---:|---:|---:|",
    ]
    for item in report["measurements"]:
        if item["status"] == "measured":
            lines.append(
                f"| {item['backend']} | {item['operation']} | {item['messageBytes']} | measured | "
                f"{item['medianMs']} | {item['operationsPerSecond']} | {item['throughputMiBPerSecond']} |"
            )
        else:
            lines.append(
                f"| {item['backend']} | {item['operation']} | {item['messageBytes']} | skipped | - | - | - |"
            )
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        sizes = [16, 1024] if args.quick else _sizes(args.sizes)
        iterations = 2 if args.quick else args.iterations
        warmup = 1 if args.quick else args.warmup
        backends = ["openssl", "gmssl"] if args.backend == "both" else [args.backend]
        openssl = runner.resolve_openssl(args.openssl) if "openssl" in backends else ""
        report = build_report(backends, sizes, iterations, warmup, openssl)
        _atomic_write(args.json, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        _atomic_write(args.markdown, render_markdown(report))
        measured = sum(item["status"] == "measured" for item in report["measurements"])
        skipped = len(report["measurements"]) - measured
        print(f"Benchmark complete: measured={measured}, skipped={skipped}")
        print(f"JSON: {args.json}\nMarkdown: {args.markdown}")
        return 0
    except (BenchmarkError, runner.RunnerError, OSError) as error:
        print(f"Error: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
