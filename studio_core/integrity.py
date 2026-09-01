"""Canonical content hashing for repository artifacts.

An ``Artifact Contract`` binds a ``content_hash`` to a ``repo://`` path, and that binding has
to mean the same thing on every checkout. Hashing the raw bytes on disk does not: Git stores
text blobs with LF endings, but a Windows checkout with ``core.autocrlf=true`` materialises
the same blob with CRLF. The raw-byte hash of a file therefore depends on who cloned it,
which turns an integrity check into a platform check and produces false tamper alarms.

The canonical representation used here is the one Git itself stores:

* **text** -- UTF-8, with every ``CRLF`` reduced to ``LF``. A lone ``CR`` is left alone,
  because Git's ``text=auto`` conversion only rewrites ``CRLF`` pairs.
* **binary** -- the raw bytes, untouched. Normalising a PNG or a zip would corrupt it.

Classification follows Git: a blob is binary when a NUL byte appears in its leading
``BINARY_SNIFF_BYTES``. Content that is neither (no NUL, but not decodable as UTF-8) is
*rejected* rather than guessed at, because the two candidate canonical forms would disagree
and a silent wrong answer here is exactly the failure this module exists to prevent.

Normalisation only collapses the ``CR`` of a ``CRLF`` pair, so it never merges two files with
different content: any change to a byte that is not part of a line terminator survives into
the digest, and tampering stays detectable.

``.gitattributes`` pins ``* text=auto`` so the repository's stored blobs actually are the LF
form this module assumes, independent of any contributor's local ``core.autocrlf``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

#: Number of leading bytes Git inspects before calling a blob binary.
BINARY_SNIFF_BYTES = 8000

#: Prefix every stored ``content_hash`` carries.
HASH_PREFIX = "sha256:"

ContentKind = Literal["text", "binary"]


class IntegrityError(ValueError):
    """Raised when content has no single well-defined canonical representation."""


@dataclass(frozen=True)
class IntegrityDecision:
    """Outcome of a canonical content-hash comparison."""

    matches: bool
    kind: ContentKind
    expected: str
    actual: str
    message: str


def classify(data: bytes, *, label: str = "<bytes>") -> ContentKind:
    """Return ``"binary"`` or ``"text"`` using Git's NUL-byte heuristic.

    Raises ``IntegrityError`` for the ambiguous middle ground -- no NUL byte, so Git would
    treat it as text and normalise it, but not valid UTF-8, so this module cannot reproduce
    that normalisation with confidence.
    """

    if b"\x00" in data[:BINARY_SNIFF_BYTES]:
        return "binary"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntegrityError(
            f"{label}: content has no NUL byte but is not valid UTF-8, so its canonical form "
            f"is ambiguous; declare it binary in .gitattributes or re-encode it as UTF-8"
        ) from exc
    return "text"


def canonical_bytes(data: bytes, *, label: str = "<bytes>") -> bytes:
    """Reduce ``data`` to the byte string Git would store for it."""

    if classify(data, label=label) == "binary":
        return data
    return data.replace(b"\r\n", b"\n")


def content_hash(data: bytes, *, label: str = "<bytes>") -> str:
    """Return the ``sha256:`` digest of the canonical representation of ``data``."""

    return HASH_PREFIX + hashlib.sha256(canonical_bytes(data, label=label)).hexdigest()


def hash_file(path: Path | str, *, label: str | None = None) -> str:
    """Return the canonical ``sha256:`` digest of the file at ``path``."""

    target = Path(path)
    return content_hash(target.read_bytes(), label=label or str(path))


def verify_file(path: Path | str, expected: str, *, label: str | None = None) -> IntegrityDecision:
    """Compare a stored ``content_hash`` against the canonical digest of a file.

    Returns a decision instead of raising so a mismatch stays auditable and the caller can
    report both digests. Missing files and ambiguous encodings still raise, because those are
    contract errors rather than integrity verdicts.
    """

    name = label or str(path)
    data = Path(path).read_bytes()
    kind = classify(data, label=name)
    actual = content_hash(data, label=name)
    if actual == expected:
        return IntegrityDecision(True, kind, expected, actual, f"{name}: canonical {kind} hash matches")
    return IntegrityDecision(
        False,
        kind,
        expected,
        actual,
        f"{name}: canonical {kind} hash is {actual}, contract records {expected}",
    )
