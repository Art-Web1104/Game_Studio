"""Deterministic repository scan for plaintext credential material.

``studio_core.collaboration.scan_for_plaintext_secrets`` answers a narrow question — does
*this* contract or evidence payload embed a credential? This module answers the repository
question that CI needs: walk the working tree once, in a stable order, and report every
credential-shaped string that is not explicitly allowlisted.

Design rules, all of which the test suite pins:

* **Deterministic.** Directory traversal, rule evaluation and the finding list are sorted, so
  the same tree always produces byte-identical output. There is no entropy heuristic, no
  wall-clock value and no dependency on filesystem iteration order.
* **Non-leaking.** A finding carries the rule id, path, line and column plus a *redacted*
  excerpt. The matched text is never returned, printed or logged, so a detection cannot move
  a secret into CI logs.
* **Maintainable.** Rules are declarative :class:`SecretRule` records and exclusions live in a
  single :class:`ScanConfig`. Adding a rule is one tuple entry plus one test.
* **Stdlib only.** The scan must keep working when the YAML dependency is unavailable.

Rule patterns are kept in code rather than in a policy file: this scanner reads the whole
repository, so a pattern stored as scannable data would have to be written so that it never
matches itself.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]

#: Marker that exempts the line it appears on *and* the line immediately after it. Placed in
#: a comment beside intentional sample values, it keeps documentation and test fixtures
#: scannable without blanket-ignoring whole files. The preceding-line form exists so that a
#: long source line can be exempted without pushing an unreadable comment onto its end.
ALLOW_MARKER = "secret-scan: allow"


@dataclass(frozen=True)
class SecretRule:
    """One credential-shaped pattern and the reason it is treated as a secret."""

    rule_id: str
    description: str
    pattern: str


#: Patterns that indicate a plaintext credential value. Each must match credential material
#: only, never the policy vocabulary this repository uses to *refer* to credentials
#: (``secret-ref://``, ``secrets_policy``, ``credential_ref`` and friends).
RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "anthropic-api-key",
        "Anthropic API key literal",
        r"\bsk-ant-[A-Za-z0-9_\-]{16,}",
    ),
    SecretRule(
        "openai-style-api-key",
        "OpenAI-style API key literal",
        r"\bsk-[A-Za-z0-9]{20,}\b",
    ),
    SecretRule(
        "github-token",
        "GitHub personal access, OAuth, user, server or refresh token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b",
    ),
    SecretRule(
        "github-fine-grained-token",
        "GitHub fine-grained personal access token",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    ),
    SecretRule(
        "slack-token",
        "Slack bot, user, app or refresh token",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    ),
    SecretRule(
        "aws-access-key-id",
        "AWS access key identifier",
        r"\bAKIA[0-9A-Z]{16}\b",
    ),
    SecretRule(
        "google-api-key",
        "Google API key literal",
        r"\bAIza[A-Za-z0-9_\-]{35}\b",
    ),
    SecretRule(
        "private-key-block",
        "PEM private key block header",
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
    ),
    SecretRule(
        "bearer-token",
        "Authorization bearer token literal",
        r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}",
    ),
    SecretRule(
        "assigned-credential",
        "Credential keyword assigned a literal value instead of a reference",
        r"(?i)\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token"
        r"|client[_-]?secret|secret[_-]?key|passwd|password)"
        r"\b\s*[:=]\s*[\"']?[A-Za-z0-9+/=_\-]{12,}",
    ),
    SecretRule(
        "json-web-token",
        "Signed JSON Web Token literal",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    ),
)

_COMPILED: dict[str, re.Pattern[str]] = {rule.rule_id: re.compile(rule.pattern) for rule in RULES}


@dataclass(frozen=True)
class ScanConfig:
    """Everything the walker excludes, in one reviewable place."""

    #: Directory names pruned anywhere in the tree (VCS metadata, caches, build output).
    ignored_directory_names: frozenset[str]
    #: Repository-relative POSIX prefixes pruned wholesale.
    ignored_path_prefixes: tuple[str, ...]
    #: Suffixes of generated or non-source files that never carry reviewable credentials.
    ignored_suffixes: frozenset[str]
    #: Compound name endings (``.min.js`` and friends) that ``Path.suffix`` cannot express.
    ignored_name_suffixes: tuple[str, ...]
    #: Repository-relative POSIX paths exempted in full. Prefer :data:`ALLOW_MARKER` instead;
    #: a path entry hides every future line of the file as well.
    allowlisted_paths: frozenset[str]
    #: Files larger than this are reported as skipped rather than read into memory.
    max_file_bytes: int

    def with_allowlist(self, paths: Iterable[str]) -> "ScanConfig":
        """Return a copy that also exempts ``paths`` (repository-relative POSIX)."""

        return replace(self, allowlisted_paths=self.allowlisted_paths | frozenset(paths))


DEFAULT_CONFIG = ScanConfig(
    ignored_directory_names=frozenset(
        {
            ".git",
            ".hg",
            ".svn",
            ".idea",
            ".vscode",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".tox",
            ".eggs",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            "dist",
            "build",
            "site-packages",
        }
    ),
    # Reviewer worktrees are scratch copies of this repository; scanning them would double
    # every finding and make the report depend on local reviewer state.
    ignored_path_prefixes=(".claude/worktrees/",),
    ignored_suffixes=frozenset(
        {
            ".pyc",
            ".pyo",
            ".pyd",
            ".so",
            ".dll",
            ".dylib",
            ".exe",
            ".bin",
            ".zip",
            ".gz",
            ".bz2",
            ".xz",
            ".tar",
            ".whl",
            ".jar",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".ico",
            ".webp",
            ".svgz",
            ".pdf",
            ".ttf",
            ".otf",
            ".woff",
            ".woff2",
            ".mp3",
            ".wav",
            ".ogg",
            ".mp4",
            ".webm",
        }
    ),
    ignored_name_suffixes=(".min.js", ".min.css", ".map", ".lock"),
    allowlisted_paths=frozenset(),
    max_file_bytes=5 * 1024 * 1024,
)


@dataclass(frozen=True)
class Finding:
    """A single credential-shaped match. ``excerpt`` never contains the matched text."""

    rule_id: str
    path: str
    line: int
    column: int
    excerpt: str

    @property
    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.path, self.line, self.column, self.rule_id)


@dataclass(frozen=True)
class SkippedFile:
    """A file the walker deliberately did not read, and why."""

    path: str
    reason: str


@dataclass(frozen=True)
class ScanReport:
    """Result of one repository scan."""

    root: str
    scanned_files: int
    skipped: tuple[SkippedFile, ...]
    findings: tuple[Finding, ...]

    @property
    def ok(self) -> bool:
        """True when no credential-shaped material survived the allowlist."""

        return not self.findings


_EXCERPT_LIMIT = 120


def _redact(line: str, start: int, end: int, rule_id: str) -> str:
    """Return ``line`` with the matched span replaced by a length-only placeholder."""

    placeholder = f"<redacted:{rule_id}:{end - start}chars>"
    prefix = line[:start].rstrip()
    suffix = line[end:].lstrip()
    excerpt = f"{prefix}{placeholder}{suffix}".strip()
    if len(excerpt) > _EXCERPT_LIMIT:
        excerpt = excerpt[:_EXCERPT_LIMIT] + "..."
    return excerpt


def scan_text(text: str, *, path: str, rules: Sequence[SecretRule] = RULES) -> list[Finding]:
    """Return every non-allowlisted match in ``text``, in deterministic order.

    A line is exempt in full when it carries :data:`ALLOW_MARKER`, or when the line directly
    above it does. That is what lets documentation and test fixtures hold realistic sample
    values without failing the repository scan.
    """

    findings: list[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        line_number = index + 1
        if ALLOW_MARKER in line or (index and ALLOW_MARKER in lines[index - 1]):
            continue
        for rule in rules:
            for match in _COMPILED[rule.rule_id].finditer(line):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        path=path,
                        line=line_number,
                        column=match.start() + 1,
                        excerpt=_redact(line, match.start(), match.end(), rule.rule_id),
                    )
                )
    findings.sort(key=lambda finding: finding.sort_key)
    return findings


def _looks_binary(data: bytes) -> bool:
    """Treat a NUL byte or undecodable content as binary, the way git does."""

    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _is_ignored_relative_path(relative: str, config: ScanConfig) -> bool:
    if any(relative.startswith(prefix) for prefix in config.ignored_path_prefixes):
        return True
    parts = relative.split("/")
    if any(part in config.ignored_directory_names for part in parts[:-1]):
        return True
    name = parts[-1]
    if Path(name).suffix.lower() in config.ignored_suffixes:
        return True
    return any(name.lower().endswith(suffix) for suffix in config.ignored_name_suffixes)


def iter_scannable_files(root: Path, config: ScanConfig = DEFAULT_CONFIG) -> list[Path]:
    """Return the candidate files under ``root`` in stable, sorted order."""

    root = root.resolve()
    candidates: list[Path] = []
    for directory, subdirectories, filenames in os.walk(root):
        current = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in config.ignored_directory_names
            and not _is_ignored_relative_path(
                (current / name).relative_to(root).as_posix() + "/", config
            )
        )
        for filename in sorted(filenames):
            path = current / filename
            if not path.is_file() or path.is_symlink():
                continue
            if _is_ignored_relative_path(path.relative_to(root).as_posix(), config):
                continue
            candidates.append(path)
    # ``os.walk`` is depth-first, so per-directory sorting is not a global order. Sort on the
    # relative POSIX path so the result is identical on every platform and filesystem.
    candidates.sort(key=lambda path: path.relative_to(root).as_posix())
    return candidates


def scan_repository(root: Path | str = ROOT, config: ScanConfig = DEFAULT_CONFIG) -> ScanReport:
    """Scan every eligible file under ``root`` and return a deterministic report."""

    root_path = Path(root).resolve()
    findings: list[Finding] = []
    skipped: list[SkippedFile] = []
    scanned = 0

    for path in iter_scannable_files(root_path, config):
        relative = path.relative_to(root_path).as_posix()
        if relative in config.allowlisted_paths:
            skipped.append(SkippedFile(relative, "ALLOWLISTED_PATH"))
            continue
        try:
            size = path.stat().st_size
        except OSError:
            skipped.append(SkippedFile(relative, "UNREADABLE"))
            continue
        if size > config.max_file_bytes:
            skipped.append(SkippedFile(relative, "TOO_LARGE"))
            continue
        try:
            data = path.read_bytes()
        except OSError:
            skipped.append(SkippedFile(relative, "UNREADABLE"))
            continue
        if _looks_binary(data):
            skipped.append(SkippedFile(relative, "BINARY"))
            continue
        scanned += 1
        findings.extend(scan_text(data.decode("utf-8"), path=relative))

    findings.sort(key=lambda finding: finding.sort_key)
    return ScanReport(
        root=root_path.as_posix(),
        scanned_files=scanned,
        skipped=tuple(skipped),
        findings=tuple(findings),
    )


def format_report(report: ScanReport, *, verbose: bool = False) -> str:
    """Render a report as stable, human-readable text with no secret material in it."""

    lines: list[str] = []
    for finding in report.findings:
        lines.append(
            f"[SECRET] {finding.path}:{finding.line}:{finding.column} "
            f"rule={finding.rule_id} :: {finding.excerpt}"
        )
    if verbose:
        for entry in report.skipped:
            lines.append(f"[SKIP] {entry.path} ({entry.reason})")
    if report.ok:
        lines.append(f"[PASS] no plaintext credential material in {report.scanned_files} files")
    else:
        lines.append(
            f"[FAIL] {len(report.findings)} finding(s) across {report.scanned_files} scanned files"
        )
    return "\n".join(lines)
