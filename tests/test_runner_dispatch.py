"""Tests for the unified GM algorithm vector runner entry point."""

from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import runner


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestUnifiedRunner(unittest.TestCase):
    def test_dispatches_sm3_vector_file(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = runner.main([str(PROJECT_ROOT / "vectors" / "sm3.json")])

        self.assertEqual(result, runner.EXIT_SUCCESS)

    def test_dispatches_sm4_vector_file(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = runner.main([str(PROJECT_ROOT / "vectors" / "sm4.json")])

        self.assertEqual(result, runner.EXIT_SUCCESS)

    def test_dispatches_hmac_sm3_vector_file(self) -> None:
        with redirect_stdout(io.StringIO()):
            result = runner.main(
                [str(PROJECT_ROOT / "vectors" / "hmac-sm3.json")]
            )

        self.assertEqual(result, runner.EXIT_SUCCESS)

    def test_rejects_unsupported_algorithm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsupported.json"
            path.write_text(
                json.dumps({"algorithm": "SM2", "testGroups": []}),
                encoding="utf-8",
            )

            with redirect_stderr(io.StringIO()):
                result = runner.main([str(path)])

        self.assertEqual(result, runner.EXIT_INPUT_ERROR)


if __name__ == "__main__":
    unittest.main()
