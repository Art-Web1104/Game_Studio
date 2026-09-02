"""Default-deny integrity gate for repository binary assets.

The defect this module replaces: ``tests/test_integrity.py`` asserted
``report['files']['binary'] == 0``. That assertion is not an integrity property. It passes
today only because no art exists yet, and the first legitimate PNG -- one traced end to end
through a READY Task Contract, a schema-valid Artifact Contract and a raw-byte SHA-256 --
would fail it. Deleting the assertion is worse: it would admit any binary at all, and a
binary is exactly the payload that a reviewer cannot read in a diff.

So the count is replaced by an invariant. A binary file in this repository is admissible only
when *every* one of the following holds, and is rejected otherwise:

1. its path sits under an allowed root with an allowed extension (``policies/binary-assets.yaml``);
2. that extension is pinned ``binary`` or ``-text`` in ``.gitattributes``;
3. the path is relative, escapes nothing, and is reached without traversing a symlink --
   all checked *before* the file is opened;
4. its bytes are not a Git LFS pointer standing in for the real asset;
5. its bytes carry nothing that matches a ``studio_core.secret_scan`` credential rule;
6. it is named by a deliverable of a Task Contract whose status is ``READY`` or later;
7. **that same task** declares its raw-byte SHA-256 -- in an Artifact Contract primary hash, an
   Artifact Contract component hash, or its asset manifest -- and the declaration matches.

Conditions 6 and 7 are one invariant, not two. Checking them independently would admit an asset
whose deliverable is declared by task A while the only hash covering it is declared by an
unrelated task B: neither task ever asserted both "this asset is mine" and "these are its
bytes", so nothing in the control plane is accountable for what was committed. The gate
therefore requires a single traceable task to carry both halves; a declaration belonging to any
other task is neither credited nor charged, so a foreign task can no more admit an asset than
it can reject one.

Hashing here is deliberately **not** ``studio_core.integrity.content_hash``. That function
collapses ``CRLF`` to ``LF`` for text, which is right for a YAML contract and catastrophic for
a PNG: a binary holding ``\\r\\n`` would then hash identically to a corrupted ``\\n`` variant.
:func:`raw_content_hash` hashes the bytes untouched. The text path in ``studio_core.integrity``
is unchanged by this module and stays the canonical form for every non-binary artifact.

An empty allowlist result is a pass, not a failure: with no binaries in the tree, the gate has
nothing to admit and nothing to reject, which is the repository's current state.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

from studio_core import secret_scan
from studio_core.integrity import IntegrityError, classify

#: Policy source of truth. Loaded, not restated: a second copy in code would drift.
POLICY_RELATIVE_PATH = "policies/binary-assets.yaml"

#: Contract every asset manifest is validated against before any of its entries is trusted.
MANIFEST_SCHEMA_RELATIVE_PATH = "contracts/asset-manifest.schema.json"

HASH_PREFIX = "sha256:"

_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

#: First bytes of a Git LFS pointer file. Git LFS is not used here, so a pointer sitting where
#: an asset should be is a substitution attempt, not a configuration detail.
LFS_POINTER_PREFIX = b"version https://git-lfs.github.com/spec/v1"

#: Directory names that are not part of the committed surface. Mirrors
#: ``scripts.validate_baseline.NON_REPOSITORY_DIRS``; kept here so the gate can walk an
#: isolated fixture root without importing the validator.
DEFAULT_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "build", "dist", "worktrees"}
)

#: Credential rules applied to raw asset bytes. ``secret_scan.scan_text`` is deliberately not
#: reused: it honours an in-band allow marker, and a binary that can exempt itself by
#: embedding a comment string is not being scanned at all.
_BINARY_SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (rule.rule_id, re.compile(rule.pattern)) for rule in secret_scan.RULES
)

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class BinaryAssetError(ValueError):
    """A binary asset, manifest entry or policy file violated the gate.

    ``code`` is a stable machine-readable reason so a caller can assert on the rejection
    rather than on prose.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class BinaryAssetPolicy:
    """The executable form of ``policies/binary-assets.yaml``."""

    policy_id: str
    policy_version: str
    mode: str
    allowed_roots: tuple[str, ...]
    allowed_extensions: tuple[str, ...]
    accepted_treatments: tuple[str, ...]
    traceable_task_status: frozenset[str]
    declaration_sources: frozenset[str]
    component_hash_suffix: str
    manifest_directory: str
    manifest_filename_template: str
    manifest_schema: str
    lfs_pointer_prefix: bytes

    def allows(self, relative: str) -> bool:
        """True when ``relative`` is inside an allowed root with an allowed extension."""

        candidate = PurePosixPath(relative)
        if candidate.suffix.lower() not in self.allowed_extensions:
            return False
        parts = candidate.parts
        return len(parts) > 1 and parts[0] in self.allowed_roots

    def manifest_name(self, task_id: str) -> str:
        return self.manifest_filename_template.format(task_id=task_id)


@dataclass(frozen=True)
class AssetDeclaration:
    """One binding of an asset path to a task, and optionally to a declared raw-byte hash."""

    path: str
    source: str
    source_ref: str
    task_id: str | None = None
    declared_hash: str | None = None
    declared_size: int | None = None


@dataclass(frozen=True)
class BinaryAssetRejection:
    """A refusal, naming the offending path and the reason in machine-readable form."""

    path: str
    code: str
    message: str


@dataclass(frozen=True)
class DeclarationIndex:
    """Every asset declaration found in the control plane, plus the malformed ones."""

    declarations: Mapping[str, tuple[AssetDeclaration, ...]]
    rejections: tuple[BinaryAssetRejection, ...]
    manifests: tuple[str, ...]

    def for_path(self, relative: str) -> tuple[AssetDeclaration, ...]:
        return tuple(self.declarations.get(relative, ()))


@dataclass(frozen=True)
class BinaryAssetReport:
    """Outcome of one gate run over a repository tree."""

    policy_id: str
    policy_version: str
    allowed_roots: tuple[str, ...]
    allowed_extensions: tuple[str, ...]
    verified: tuple[str, ...]
    rejections: tuple[BinaryAssetRejection, ...]
    manifests: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.rejections

    @property
    def count(self) -> int:
        """Number of binaries that passed every invariant. Zero is a valid answer."""

        return len(self.verified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "allowed_roots": list(self.allowed_roots),
            "allowed_extensions": list(self.allowed_extensions),
            "count": self.count,
            "verified": list(self.verified),
            "manifests": list(self.manifests),
            "rejections": [
                {"path": item.path, "code": item.code, "message": item.message} for item in self.rejections
            ],
        }


# --------------------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------------------


def load_policy(root: Path | str) -> BinaryAssetPolicy:
    """Load and structurally check the binary-asset policy under ``root``."""

    base = Path(root)
    path = base / POLICY_RELATIVE_PATH
    if not path.is_file():
        raise BinaryAssetError("POLICY_MISSING", f"{POLICY_RELATIVE_PATH} is required by the binary asset gate")
    with path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, Mapping):
        raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: root must be a mapping")

    def _require(container: Any, key: str, label: str) -> Any:
        if not isinstance(container, Mapping) or key not in container:
            raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: {label} is required")
        return container[key]

    mode = document.get("mode")
    if mode != "deny_by_default":
        raise BinaryAssetError(
            "POLICY_NOT_DEFAULT_DENY",
            f"{POLICY_RELATIVE_PATH}: mode must be 'deny_by_default', found {mode!r}",
        )

    allowlist = _require(document, "allowlist", "allowlist")
    roots = tuple(_require(allowlist, "roots", "allowlist.roots"))
    extensions = tuple(str(item).lower() for item in _require(allowlist, "extensions", "allowlist.extensions"))
    if not roots or not extensions:
        raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: the allowlist must not be empty")
    for item in roots:
        if not isinstance(item, str) or not item or "/" in item or item in {".", ".."}:
            raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: invalid allowlist root {item!r}")
    for item in extensions:
        if not item.startswith(".") or len(item) < 2:
            raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: invalid allowlist extension {item!r}")

    attributes = _require(document, "gitattributes", "gitattributes")
    treatments = tuple(str(item) for item in _require(attributes, "accepted_treatments", "gitattributes.accepted_treatments"))
    if not treatments:
        raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: no accepted .gitattributes treatments")

    hashing = _require(document, "hashing", "hashing")
    if hashing.get("algorithm") != "sha256" or hashing.get("representation") != "raw_bytes":
        raise BinaryAssetError(
            "POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: binary hashing must be sha256 over raw bytes"
        )
    if hashing.get("text_normalization") != "prohibited":
        raise BinaryAssetError(
            "POLICY_NORMALISATION_ALLOWED",
            f"{POLICY_RELATIVE_PATH}: text normalisation must stay prohibited for binary assets",
        )

    traceability = _require(document, "traceability", "traceability")
    statuses = frozenset(str(item) for item in _require(traceability, "traceable_task_status", "traceability.traceable_task_status"))
    if not statuses or "DRAFT" in statuses:
        raise BinaryAssetError(
            "POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: traceable task status must be non-empty and exclude DRAFT"
        )
    sources = frozenset(str(item) for item in _require(traceability, "declaration_sources", "traceability.declaration_sources"))
    if not sources:
        raise BinaryAssetError("POLICY_INVALID", f"{POLICY_RELATIVE_PATH}: no hash declaration sources")

    manifest = _require(document, "manifest", "manifest")
    lfs = _require(document, "git_lfs", "git_lfs")

    return BinaryAssetPolicy(
        policy_id=str(document.get("policy_id", "BINARY-ASSETS")),
        policy_version=str(document.get("policy_version", "BINARY-ASSETS/1.0.0")),
        mode=str(mode),
        allowed_roots=roots,
        allowed_extensions=extensions,
        accepted_treatments=treatments,
        traceable_task_status=statuses,
        declaration_sources=sources,
        component_hash_suffix=str(traceability.get("artifact_component_suffix", "_hash")),
        manifest_directory=str(_require(manifest, "directory", "manifest.directory")),
        manifest_filename_template=str(_require(manifest, "filename_template", "manifest.filename_template")),
        manifest_schema=str(manifest.get("schema", MANIFEST_SCHEMA_RELATIVE_PATH)),
        lfs_pointer_prefix=str(_require(lfs, "pointer_prefix", "git_lfs.pointer_prefix")).encode("utf-8"),
    )


# --------------------------------------------------------------------------------------
# raw-byte hashing -- never the text canonical form
# --------------------------------------------------------------------------------------


def raw_content_hash(data: bytes) -> str:
    """Return ``sha256:<hex>`` over ``data`` exactly as given, with no normalisation."""

    return HASH_PREFIX + hashlib.sha256(data).hexdigest()


def raw_hash_file(path: Path | str) -> str:
    """Return the raw-byte digest of the file at ``path``."""

    return raw_content_hash(Path(path).read_bytes())


def is_declared_hash(value: Any) -> bool:
    """True when ``value`` is a well-formed ``sha256:<64 lowercase hex>`` string."""

    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None


# --------------------------------------------------------------------------------------
# path safety -- every check here runs before the target file is opened
# --------------------------------------------------------------------------------------


def normalise_declared_path(declared: Any) -> str:
    """Return ``declared`` as a safe repository-relative POSIX path, or raise.

    Rejects absolute paths, Windows drive letters, UNC prefixes, backslash separators,
    ``..`` escapes, ``.`` segments and control characters. None of these needs the file to
    exist, which is the point: a hostile manifest entry must never reach an ``open()``.
    """

    if not isinstance(declared, str) or not declared.strip():
        raise BinaryAssetError("ASSET_PATH_EMPTY", "asset path must be a non-empty string")
    if "\\" in declared:
        raise BinaryAssetError("ASSET_PATH_BACKSLASH", f"asset path must use '/' separators: {declared!r}")
    if any(character in declared for character in ("\x00", "\r", "\n")):
        raise BinaryAssetError("ASSET_PATH_CONTROL_CHARACTER", f"asset path contains a control character: {declared!r}")
    if declared.startswith("/") or _WINDOWS_DRIVE.match(declared) is not None:
        raise BinaryAssetError("ASSET_PATH_ABSOLUTE", f"asset path must be repository-relative: {declared!r}")
    if declared.startswith("repo://"):
        raise BinaryAssetError("ASSET_PATH_SCHEME", f"asset path must not carry a URI scheme: {declared!r}")

    parts = declared.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        code = "ASSET_PATH_ESCAPE" if ".." in parts else "ASSET_PATH_NOT_NORMALISED"
        raise BinaryAssetError(code, f"asset path must not contain '.', '..' or empty segments: {declared!r}")
    return "/".join(parts)


def resolve_within(root: Path | str, relative: str) -> Path:
    """Return the on-disk path for ``relative``, refusing symlinks and root escapes.

    No byte of the target is read. The whole chain from ``root`` down is checked, because a
    symlinked *directory* redirects just as effectively as a symlinked file.
    """

    base = Path(root)
    safe = normalise_declared_path(relative)
    current = base
    for part in safe.split("/"):
        current = current / part
        if current.is_symlink():
            raise BinaryAssetError(
                "ASSET_SYMLINK",
                f"{safe}: a symlink is not an auditable asset (at {current.relative_to(base).as_posix()})",
            )
    try:
        resolved_root = base.resolve(strict=False)
        resolved = current.resolve(strict=False)
        resolved.relative_to(resolved_root)
    except (ValueError, OSError) as exc:
        raise BinaryAssetError("ASSET_PATH_ESCAPE", f"{safe}: resolves outside the repository root") from exc
    return current


# --------------------------------------------------------------------------------------
# byte-level refusals
# --------------------------------------------------------------------------------------


def is_lfs_pointer(data: bytes, *, prefix: bytes = LFS_POINTER_PREFIX) -> bool:
    """True when ``data`` is a Git LFS pointer standing in for a real asset."""

    return data.lstrip(b"\r\n \t").startswith(prefix)


def credential_rule_ids(data: bytes) -> tuple[str, ...]:
    """Return the ids of every ``studio_core.secret_scan`` rule matching ``data``.

    ``latin-1`` maps each byte to exactly one character, so an ASCII credential embedded
    anywhere in a binary survives the decode unchanged and stays matchable. Only rule ids are
    returned; the matched bytes are never surfaced, so a detection cannot leak the secret.
    """

    text = data.decode("latin-1")
    return tuple(sorted({rule_id for rule_id, pattern in _BINARY_SECRET_RULES if pattern.search(text)}))


# --------------------------------------------------------------------------------------
# .gitattributes cross-check
# --------------------------------------------------------------------------------------


def gitattributes_binary_extensions(text: str, *, treatments: Sequence[str] = ("binary", "-text")) -> frozenset[str]:
    """Return every ``.ext`` that ``text`` pins to a binary treatment."""

    pinned: set[str] = set()
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        pattern = fields[0]
        if not pattern.startswith("*.") or not any(item in fields[1:] for item in treatments):
            continue
        pinned.add(pattern[1:].lower())
    return frozenset(pinned)


def unpinned_extensions(policy: BinaryAssetPolicy, attributes_text: str) -> tuple[str, ...]:
    """Return the policy-allowed extensions that ``.gitattributes`` does not pin as binary."""

    pinned = gitattributes_binary_extensions(attributes_text, treatments=policy.accepted_treatments)
    return tuple(sorted(item for item in policy.allowed_extensions if item not in pinned))


# --------------------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------------------


def select_binary_files(root: Path | str, files: Iterable[Path]) -> tuple[str, ...]:
    """Return the repository-relative POSIX paths of ``files`` that classify as binary.

    Classification is ``studio_core.integrity.classify`` -- the same Git NUL-byte rule the
    text path uses -- so the gate and the content-integrity step can never disagree about
    what counts as a binary. Symlinks are excluded here and refused separately, before any
    read: classifying one would already have followed it.
    """

    base = Path(root)
    found: list[str] = []
    for path in files:
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(base).as_posix()
        try:
            if classify(path.read_bytes(), label=relative) == "binary":
                found.append(relative)
        except IntegrityError:
            # Ambiguous encoding is the text path's failure to report, not this gate's.
            continue
    return tuple(sorted(found))


def iter_binary_files(root: Path | str, *, skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS) -> tuple[str, ...]:
    """Walk ``root`` and return every binary file on the committed surface."""

    base = Path(root)
    candidates: list[Path] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if skip_dirs.intersection(path.relative_to(base).parts[:-1]):
            continue
        candidates.append(path)
    return select_binary_files(base, candidates)


def allowlisted_files(root: Path | str, policy: BinaryAssetPolicy) -> tuple[str, ...]:
    """Return every existing file under an allowed root that carries an allowed extension.

    These are candidates regardless of how ``classify`` reads them. A Git LFS pointer
    substituted for a PNG holds no NUL byte, so it classifies as *text*: gating only on the
    binary classification would let exactly the substitution AC-010 forbids walk straight
    past the gate.
    """

    base = Path(root)
    found: list[str] = []
    for asset_root in policy.allowed_roots:
        start = base / asset_root
        if not start.is_dir():
            continue
        for path in sorted(start.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(base).as_posix()
            if policy.allows(relative):
                found.append(relative)
    return tuple(sorted(set(found)))


def symlink_rejections(root: Path | str, policy: BinaryAssetPolicy) -> tuple[BinaryAssetRejection, ...]:
    """Return a rejection for every symlink found under an allowed asset root.

    A symlink is refused whatever it points at and whatever its extension is: it is the one
    entry whose committed bytes and resolved bytes are different things.
    """

    base = Path(root)
    rejections: list[BinaryAssetRejection] = []
    for asset_root in policy.allowed_roots:
        start = base / asset_root
        if not start.exists():
            continue
        for directory, subdirectories, filenames in os.walk(start, followlinks=False):
            current = Path(directory)
            for name in sorted(subdirectories) + sorted(filenames):
                entry = current / name
                if not entry.is_symlink():
                    continue
                rejections.append(
                    BinaryAssetRejection(
                        entry.relative_to(base).as_posix(),
                        "ASSET_SYMLINK",
                        f"{entry.relative_to(base).as_posix()}: a symlink under an asset root is refused unread",
                    )
                )
    return tuple(sorted(rejections, key=lambda item: item.path))


# --------------------------------------------------------------------------------------
# declarations
# --------------------------------------------------------------------------------------


def _default_manifest_validator() -> Callable[[Any, dict[str, Any]], None]:
    """Return the repository's JSON Schema validator.

    Imported lazily and from inside the function: ``scripts.validate_baseline`` imports this
    module, so a module-level import would close the cycle.
    """

    from scripts.validate_baseline import validate_instance

    return validate_instance


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def collect_declarations(
    root: Path | str,
    policy: BinaryAssetPolicy,
    *,
    manifest_validator: Callable[[Any, dict[str, Any]], None] | None = None,
) -> DeclarationIndex:
    """Index every asset declaration in ``tasks/``, ``artifacts/`` and the asset manifests."""

    base = Path(root)
    validator = manifest_validator or _default_manifest_validator()
    declarations: dict[str, list[AssetDeclaration]] = {}
    rejections: list[BinaryAssetRejection] = []
    manifests: list[str] = []

    def _record(declaration: AssetDeclaration) -> None:
        declarations.setdefault(declaration.path, []).append(declaration)

    def _asset_path(candidate: Any) -> str | None:
        """Return ``candidate`` as a safe allowlisted asset path, or None if it is not one."""

        if not isinstance(candidate, str):
            return None
        stripped = candidate.removeprefix("repo://")
        try:
            safe = normalise_declared_path(stripped)
        except BinaryAssetError:
            return None
        return safe if policy.allows(safe) else None

    # -- Task Contracts: which asset a deliverable claims, and whether the task is open ----
    tasks_dir = base / "tasks"
    for path in sorted(tasks_dir.glob("*.json")) if tasks_dir.is_dir() else []:
        contract = _load_json(path)
        if not isinstance(contract, Mapping):
            continue
        if contract.get("status") not in policy.traceable_task_status:
            continue
        task_id = contract.get("task_id")
        source_ref = path.relative_to(base).as_posix()
        for deliverable in contract.get("deliverables", []) or []:
            asset = _asset_path(deliverable.get("target_uri") if isinstance(deliverable, Mapping) else None)
            if asset is not None:
                _record(AssetDeclaration(asset, "task-deliverable", source_ref, task_id=task_id))

    # -- Artifact Contracts: the primary hash, and component hashes in ``specification`` ---
    artifacts_dir = base / "artifacts"
    for path in sorted(artifacts_dir.glob("*.json")) if artifacts_dir.is_dir() else []:
        artifact = _load_json(path)
        if not isinstance(artifact, Mapping):
            continue
        source_ref = path.relative_to(base).as_posix()
        task_id = artifact.get("task_id")
        primary = _asset_path(artifact.get("uri"))
        if primary is not None:
            _record(
                AssetDeclaration(
                    primary,
                    "artifact-primary",
                    source_ref,
                    task_id=task_id,
                    declared_hash=artifact.get("content_hash"),
                )
            )
        specification = artifact.get("specification")
        if isinstance(specification, Mapping):
            suffix = policy.component_hash_suffix
            for key, value in specification.items():
                if not isinstance(key, str) or not key.endswith(suffix) or not is_declared_hash(value):
                    continue
                component = _asset_path(specification.get(key[: -len(suffix)]))
                if component is not None:
                    _record(
                        AssetDeclaration(
                            component, "artifact-component", f"{source_ref}#{key}", task_id=task_id, declared_hash=value
                        )
                    )

    # -- Asset manifests: the task-scoped path + raw-byte hash declaration -----------------
    manifest_dir = base / policy.manifest_directory
    schema_path = base / policy.manifest_schema
    schema: dict[str, Any] | None = None
    if schema_path.is_file():
        loaded = _load_json(schema_path)
        schema = loaded if isinstance(loaded, dict) else None
    for path in sorted(manifest_dir.glob("*.json")) if manifest_dir.is_dir() else []:
        relative = path.relative_to(base).as_posix()
        manifests.append(relative)
        try:
            document = _load_json(path)
        except json.JSONDecodeError as exc:
            rejections.append(BinaryAssetRejection(relative, "MANIFEST_UNREADABLE", f"{relative}: {exc}"))
            continue
        if schema is None:
            rejections.append(
                BinaryAssetRejection(
                    relative, "MANIFEST_SCHEMA_MISSING", f"{relative}: {policy.manifest_schema} is required"
                )
            )
            continue
        try:
            validator(document, schema)
        except Exception as exc:  # the validator raises its own error type
            rejections.append(
                BinaryAssetRejection(relative, "MANIFEST_SCHEMA_INVALID", f"{relative}: {exc}")
            )
            continue
        task_id = document["task_id"]
        if path.name != policy.manifest_name(task_id):
            rejections.append(
                BinaryAssetRejection(
                    relative,
                    "MANIFEST_FILENAME_MISMATCH",
                    f"{relative}: filename must be {policy.manifest_name(task_id)} for task {task_id}",
                )
            )
            continue
        for entry in document["assets"]:
            declared = entry["path"]
            try:
                safe = normalise_declared_path(declared)
                resolve_within(base, safe)
            except BinaryAssetError as exc:
                rejections.append(BinaryAssetRejection(str(declared), exc.code, f"{relative}: {exc.message}"))
                continue
            if not policy.allows(safe):
                rejections.append(
                    BinaryAssetRejection(
                        safe,
                        "ASSET_NOT_ALLOWLISTED",
                        f"{relative}: {safe} is outside the allowed roots {list(policy.allowed_roots)!r} "
                        f"or extensions {list(policy.allowed_extensions)!r}",
                    )
                )
                continue
            if not (base / safe).is_file():
                rejections.append(
                    BinaryAssetRejection(safe, "MANIFEST_TARGET_MISSING", f"{relative}: declares a missing file {safe}")
                )
                continue
            _record(
                AssetDeclaration(
                    safe,
                    "asset-manifest",
                    relative,
                    task_id=task_id,
                    declared_hash=entry["content_hash"],
                    declared_size=entry["byte_size"],
                )
            )

    return DeclarationIndex(
        declarations={key: tuple(value) for key, value in declarations.items()},
        rejections=tuple(rejections),
        manifests=tuple(manifests),
    )


# --------------------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------------------


def evaluate_asset(
    root: Path | str,
    relative: str,
    index: DeclarationIndex,
    policy: BinaryAssetPolicy,
) -> BinaryAssetRejection | None:
    """Return the reason ``relative`` is refused, or ``None`` when it satisfies every rule.

    The order is load-bearing: path shape, then symlink and escape, then the allowlist, and
    only then is the file opened. AC-008 requires the refusals above to happen unread.

    Traceability and the hash declaration are resolved together, against the same ``task_id``:
    see the module docstring for why splitting them into two independent existence checks is
    the difference between an audit trail and two unrelated facts that happen to coexist.
    """

    base = Path(root)
    try:
        safe = normalise_declared_path(relative)
    except BinaryAssetError as exc:
        return BinaryAssetRejection(str(relative), exc.code, exc.message)

    try:
        target = resolve_within(base, safe)
    except BinaryAssetError as exc:
        return BinaryAssetRejection(safe, exc.code, exc.message)

    if not policy.allows(safe):
        return BinaryAssetRejection(
            safe,
            "ASSET_NOT_ALLOWLISTED",
            f"{safe}: binary assets are default-deny; allowed roots are {list(policy.allowed_roots)!r} "
            f"and allowed extensions are {list(policy.allowed_extensions)!r}",
        )

    if not target.is_file():
        return BinaryAssetRejection(safe, "ASSET_MISSING", f"{safe}: the asset does not exist")

    data = target.read_bytes()

    if is_lfs_pointer(data, prefix=policy.lfs_pointer_prefix):
        return BinaryAssetRejection(
            safe,
            "ASSET_LFS_POINTER",
            f"{safe}: a Git LFS pointer was substituted for the asset; the pointer's hash must never "
            f"stand in for the asset's raw bytes",
        )

    matched_rules = credential_rule_ids(data)
    if matched_rules:
        return BinaryAssetRejection(
            safe,
            "ASSET_CREDENTIAL_LIKE",
            f"{safe}: credential-shaped bytes matched {list(matched_rules)!r}; an allowlisted path and "
            f"extension do not exempt an asset from the secret scan",
        )

    declarations = index.for_path(safe)

    # The set of tasks that both hold a traceable status and claim this asset as their own
    # deliverable. A declaration without a ``task_id`` cannot be bound to a hash declaration,
    # so it traces nothing and is not eligible.
    eligible_tasks = {
        item.task_id
        for item in declarations
        if item.source == "task-deliverable" and isinstance(item.task_id, str) and item.task_id
    }
    if not eligible_tasks:
        return BinaryAssetRejection(
            safe,
            "ASSET_UNTRACKED_BY_TASK",
            f"{safe}: no Task Contract with status in {sorted(policy.traceable_task_status)!r} declares this "
            f"asset as a deliverable under a task_id",
        )

    # Only declarations made by an eligible task count. Everything else is ignored outright,
    # which is what keeps an unrelated task from *poisoning* the check as well as from
    # satisfying it: a foreign hash -- right or wrong -- is not evidence about this asset.
    hashed = [item for item in declarations if item.declared_hash is not None and item.task_id in eligible_tasks]
    if not hashed:
        foreign = sorted(
            {
                f"{item.source_ref} (task {item.task_id!r})"
                for item in declarations
                if item.declared_hash is not None
            }
        )
        if foreign:
            return BinaryAssetRejection(
                safe,
                "ASSET_HASH_CROSS_TASK",
                f"{safe}: the only raw-byte hash declarations come from tasks that do not declare this asset "
                f"as a deliverable ({'; '.join(foreign)}); one of {sorted(eligible_tasks)!r} must declare the "
                f"hash itself",
            )
        return BinaryAssetRejection(
            safe,
            "ASSET_HASH_UNDECLARED",
            f"{safe}: none of {sorted(eligible_tasks)!r} declares a raw-byte hash by an Artifact Contract "
            f"primary hash, an Artifact Contract component hash, or an entry in {policy.manifest_directory}/",
        )

    actual = raw_content_hash(data)
    for declaration in hashed:
        if not is_declared_hash(declaration.declared_hash):
            return BinaryAssetRejection(
                safe,
                "ASSET_HASH_MALFORMED",
                f"{safe}: {declaration.source_ref} declares {declaration.declared_hash!r}, which is not "
                f"sha256:<64 lowercase hex>",
            )
        if declaration.declared_hash != actual:
            return BinaryAssetRejection(
                safe,
                "ASSET_HASH_MISMATCH",
                f"{safe}: {declaration.source_ref} declares {declaration.declared_hash}, but the raw bytes "
                f"hash to {actual}",
            )
        if declaration.declared_size is not None and declaration.declared_size != len(data):
            return BinaryAssetRejection(
                safe,
                "ASSET_SIZE_MISMATCH",
                f"{safe}: {declaration.source_ref} declares {declaration.declared_size} bytes, but the file "
                f"holds {len(data)}",
            )
    return None


def validate_binary_assets(
    root: Path | str,
    binaries: Sequence[str] | None = None,
    *,
    policy: BinaryAssetPolicy | None = None,
    manifest_validator: Callable[[Any, dict[str, Any]], None] | None = None,
) -> BinaryAssetReport:
    """Run the full gate over ``root`` and return an auditable report.

    ``binaries`` is the set of repository-relative binary paths already discovered by the
    caller; passing it lets the baseline validator classify the tree once. When omitted the
    tree is walked here. A tree with no binaries produces an empty, passing report.
    """

    base = Path(root)
    active = policy or load_policy(base)
    discovered = tuple(binaries) if binaries is not None else iter_binary_files(base)

    rejections: list[BinaryAssetRejection] = []

    attributes_path = base / ".gitattributes"
    if not attributes_path.is_file():
        rejections.append(
            BinaryAssetRejection(
                ".gitattributes",
                "GITATTRIBUTES_MISSING",
                ".gitattributes is required so Git stores allowed binary extensions verbatim",
            )
        )
    else:
        for extension in unpinned_extensions(active, attributes_path.read_text(encoding="utf-8")):
            rejections.append(
                BinaryAssetRejection(
                    ".gitattributes",
                    "EXTENSION_NOT_PINNED_BINARY",
                    f".gitattributes does not pin '*{extension}' to {list(active.accepted_treatments)!r}, so Git "
                    f"may line-ending normalise an allowed binary asset",
                )
            )

    rejections.extend(symlink_rejections(base, active))

    index = collect_declarations(base, active, manifest_validator=manifest_validator)
    rejections.extend(index.rejections)

    # The candidate set is the union of what the tree classifies as binary and what merely
    # *occupies* an allowed asset path. The second half is what makes an LFS pointer -- plain
    # text, and therefore not a binary -- reachable by the gate at all.
    candidates = sorted(set(discovered) | set(allowlisted_files(base, active)))

    verified: list[str] = []
    for relative in candidates:
        rejection = evaluate_asset(base, relative, index, active)
        if rejection is None:
            verified.append(relative)
        else:
            rejections.append(rejection)

    return BinaryAssetReport(
        policy_id=active.policy_id,
        policy_version=active.policy_version,
        allowed_roots=active.allowed_roots,
        allowed_extensions=active.allowed_extensions,
        verified=tuple(sorted(verified)),
        rejections=tuple(rejections),
        manifests=index.manifests,
    )


def format_rejections(rejections: Sequence[BinaryAssetRejection]) -> str:
    """Render refusals as one stable line each, for a validator error message."""

    return "; ".join(f"[{item.code}] {item.message}" for item in rejections)
