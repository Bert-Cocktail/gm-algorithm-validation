#!/usr/bin/env python3
"""Generate a reproducible manifest for local ACVP-style requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import acvp_adapter


MANIFEST_SCHEMA = (
    Path(__file__).resolve().parent / "acvp" / "schemas" / "manifest-schema.json"
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate an ACVP request manifest.")
    parser.add_argument("--request-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def build_manifest(request_dir: Path) -> dict:
    if not request_dir.is_dir():
        raise acvp_adapter.AdapterError(f"request directory not found: {request_dir}")
    request_paths = sorted(request_dir.glob("*-request.json"), key=lambda path: path.name)
    if not request_paths:
        raise acvp_adapter.AdapterError(
            f"no *-request.json files found in: {request_dir}"
        )

    files = []
    seen_vs_ids: set[int] = set()
    total_tests = 0
    for path in request_paths:
        _version, request = acvp_adapter.load_request(path)
        vs_id = request["vsId"]
        if vs_id in seen_vs_ids:
            raise acvp_adapter.AdapterError(f"duplicate vsId across request files: {vs_id}")
        seen_vs_ids.add(vs_id)
        raw = path.read_bytes()
        tests = sum(len(group["tests"]) for group in request["testGroups"])
        total_tests += tests
        files.append(
            {
                "file": path.name,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "vsId": vs_id,
                "algorithm": request["algorithm"],
                "tests": tests,
            }
        )

    manifest = {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "requestDirectory": str(request_dir.resolve()),
        "summary": {"files": len(files), "tests": total_tests},
        "files": files,
    }
    acvp_adapter.validate_schema(manifest, MANIFEST_SCHEMA, "manifest")
    return manifest


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        request_paths = list(args.request_dir.glob("*-request.json")) if args.request_dir.is_dir() else []
        if any(args.output.resolve() == path.resolve() for path in request_paths):
            raise acvp_adapter.AdapterError("manifest must not overwrite a request file")
        manifest = build_manifest(args.request_dir)
        acvp_adapter._atomic_write_json(args.output, manifest)
        print(
            f"Manifest: Files={manifest['summary']['files']}, "
            f"Tests={manifest['summary']['tests']}, Output={args.output}"
        )
        return acvp_adapter.EXIT_SUCCESS
    except (acvp_adapter.AdapterError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return acvp_adapter.EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
