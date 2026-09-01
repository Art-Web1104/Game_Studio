#!/usr/bin/env python3
"""CLI wrapper around the deterministic repository secret scan.

Exit codes are the contract CI depends on:

* ``0`` -- no credential-shaped material survived the allowlist.
* ``1`` -- at least one finding; the run fails.
* ``2`` -- the scan could not run (bad root, unreadable tree).

The rules, exclusions and redaction live in :mod:`studio_core.secret_scan`; this file only
parses arguments and turns a report into an exit code, so the engine stays unit-testable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from studio_core.secret_scan import (  # noqa: E402  (path bootstrap must precede the import)
    DEFAULT_CONFIG,
    ScanReport,
    format_report,
    scan_repository,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan_secrets",
        description="Scan a working tree for plaintext credential material.",
    )
    parser.add_argument(
        "--root",
        default=str(ROOT),
        help="directory to scan (defaults to the repository root)",
    )
    parser.add_argument(
        "--allow-path",
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="repository-relative POSIX path to exempt in full; repeatable",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="also list the files that were skipped and why",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> tuple[int, str]:
    """Return the exit code and the rendered report for ``argv``."""

    arguments = build_parser().parse_args(argv)
    root = Path(arguments.root)
    if not root.is_dir():
        return EXIT_ERROR, f"[ERROR] scan root is not a directory: {arguments.root}"

    config = DEFAULT_CONFIG.with_allowlist(arguments.allow_path)
    try:
        report: ScanReport = scan_repository(root, config)
    except OSError as exc:
        return EXIT_ERROR, f"[ERROR] repository scan failed: {exc}"

    rendered = format_report(report, verbose=arguments.verbose)
    return (EXIT_OK if report.ok else EXIT_FINDINGS), rendered


def main(argv: Sequence[str] | None = None) -> int:
    code, rendered = run(argv)
    print(rendered, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
