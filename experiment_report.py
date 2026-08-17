#!/usr/bin/env python3
"""Generate an archival Markdown report from structured validation results."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import acvp_adapter


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a validation report.")
    parser.add_argument("--vector-summary", type=Path, required=True)
    parser.add_argument("--acvp-summary", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--capabilities", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    return parser.parse_args(argv)


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as error:
        raise acvp_adapter.AdapterError(f"{label} not found: {path}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise acvp_adapter.AdapterError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise acvp_adapter.AdapterError(f"{label} must contain a JSON object")
    return value


def _command_version(command: list[str], fallback: str) -> str:
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return fallback
    output = (process.stdout or process.stderr).strip()
    return output.splitlines()[0] if process.returncode == 0 and output else fallback


def collect_environment(openssl: str) -> dict[str, str]:
    try:
        gmssl_version = importlib.metadata.version("gmssl")
    except importlib.metadata.PackageNotFoundError:
        gmssl_version = "not installed"
    return {
        "Python": sys.version.split()[0],
        "OpenSSL": _command_version([openssl, "version"], "unavailable"),
        "gmssl": gmssl_version,
        "Git HEAD": _command_version(
            ["git", "rev-parse", "--short", "HEAD"], "unavailable"
        ),
    }


def build_report(
    vector_summary: dict[str, Any],
    acvp_summary: dict[str, Any],
    manifest: dict[str, Any],
    environment: dict[str, str],
    capabilities: dict[str, Any] | None = None,
) -> str:
    vector = vector_summary.get("summary", {})
    acvp = acvp_summary.get("summary", {})
    lines = [
        "# GM Algorithm Validation 实验报告",
        "",
        f"生成时间：{datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}",
        "",
        "## 环境",
        "",
        "| 项目 | 版本或标识 |",
        "|---|---|",
    ]
    lines.extend(f"| {name} | {value} |" for name, value in environment.items())
    lines.extend(
        [
            "",
            "## 回归向量验证",
            "",
            f"- 后端：`{vector_summary.get('backend', 'unknown')}`",
            f"- 状态：`{vector_summary.get('status', 'unknown')}`",
            f"- 文件：{vector.get('files', 0)}",
            f"- 测试：{vector.get('tests', 0)}",
            f"- 通过：{vector.get('passedTests', 0)}",
            f"- 失败：{vector.get('failedTests', 0)}",
            "",
            "## ACVP 风格请求处理",
            "",
            f"- 后端：`{acvp_summary.get('backend', 'unknown')}`",
            f"- 状态：`{acvp_summary.get('status', 'unknown')}`",
            f"- 请求文件：{acvp.get('files', 0)}",
            f"- 测试：{acvp.get('tests', 0)}",
            f"- 后端不一致：{acvp.get('backendMismatches', 0)}",
            "",
            "## 请求清单",
            "",
            "| 文件 | SHA-256 | vsId | 算法 | 测试数 |",
            "|---|---|---:|---|---:|",
        ]
    )
    for item in manifest.get("files", []):
        lines.append(
            f"| {item['file']} | `{item['sha256']}` | {item['vsId']} | "
            f"{item['algorithm']} | {item['tests']} |"
        )
    if capabilities is not None:
        lines.extend(
            [
                "",
                "## 能力快照",
                "",
                "| 本地算法 | 标准或实验说明 | 操作 | ACVP 标识状态 |",
                "|---|---|---|---|",
            ]
        )
        for item in capabilities.get("algorithms", []):
            mapping = item.get("identifierMapping", {})
            operations = item.get("operations", item.get("directions", []))
            lines.append(
                f"| {item.get('algorithm', '')} | {mapping.get('standardIdentifier', '')} | "
                f"{', '.join(operations) if operations else 'AFT'} | "
                f"{mapping.get('acvpStatus', '')} |"
            )
    lines.extend(
        [
            "",
            "## 结论与范围",
            "",
            "当前结果证明仓库中的已记录输入在所选本地后端上通过验证，并可通过请求哈希复现实验输入。",
            "本项目不连接 NIST ACVTS，报告不是算法认证证书，也不代表生产安全审计。",
            "SM3/SM4 的 MCT 与 LDT 尚无本项目采用的权威 ACVP 规则，因此当前只执行 AFT。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_report(path: Path, report: str) -> None:
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as report_file:
            report_file.write(report)
            report_file.flush()
            os.fsync(report_file.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        inputs = [args.vector_summary, args.acvp_summary, args.manifest]
        if args.capabilities is not None:
            inputs.append(args.capabilities)
        if any(args.output.resolve() == path.resolve() for path in inputs):
            raise acvp_adapter.AdapterError("report output must not overwrite an input")
        capabilities = (
            _read_object(args.capabilities, "capabilities")
            if args.capabilities is not None else None
        )
        if capabilities is not None:
            acvp_adapter.validate_schema(
                capabilities, acvp_adapter.CAPABILITIES_SCHEMA, "capabilities"
            )
        report = build_report(
            _read_object(args.vector_summary, "vector summary"),
            _read_object(args.acvp_summary, "ACVP summary"),
            _read_object(args.manifest, "manifest"),
            collect_environment(args.openssl),
            capabilities,
        )
        if not args.output.parent.is_dir():
            raise acvp_adapter.AdapterError(
                f"report output directory not found: {args.output.parent}"
            )
        _write_report(args.output, report)
        print(f"Report written: {args.output}")
        return acvp_adapter.EXIT_SUCCESS
    except (acvp_adapter.AdapterError, OSError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return acvp_adapter.EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
