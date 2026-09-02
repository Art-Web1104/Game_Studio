"""Tests for the SYS-AST-0014 default-deny binary asset integrity gate.

The gate replaces a hardcoded "the repository holds no binary" assertion with an invariant,
so this suite has to prove both halves of that trade at once:

* a binary that is fully traced -- allowlisted path and extension, pinned in ``.gitattributes``,
  named by a ``READY`` task deliverable, declared with its raw-byte SHA-256 -- is **admitted**;
* every other shape is **refused**, with a stable machine-readable code.

Two rules shape how the fixtures are built, and both are acceptance criteria rather than
style preferences:

* **No binary is committed.** AC-014 forbids this task from adding any art or binary file to
  the repository, so every fixture -- positive and negative -- is written into a
  ``tempfile.TemporaryDirectory`` at runtime and removed when the test ends. The shipped
  policy, manifest schema and ``.gitattributes`` are *copied* into that scratch root, so the
  negative cases exercise the real artifacts rather than a restatement of them.
* **No literal credential appears here.** The repository secret scan reads ``tests/`` too, so
  the credential-shaped sample used for AC-009 is assembled from fragments at runtime, the
  same discipline ``tests/test_secret_scan.py`` follows.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest
from typing import Any, Iterable

import yaml

from studio_core import secret_scan
from studio_core.binary_assets import (
    HASH_PREFIX,
    LFS_POINTER_PREFIX,
    BinaryAssetError,
    BinaryAssetRejection,
    BinaryAssetReport,
    allowlisted_files,
    collect_declarations,
    credential_rule_ids,
    evaluate_asset,
    format_rejections,
    gitattributes_binary_extensions,
    is_declared_hash,
    is_lfs_pointer,
    iter_binary_files,
    load_policy,
    normalise_declared_path,
    raw_content_hash,
    raw_hash_file,
    resolve_within,
    select_binary_files,
    unpinned_extensions,
    validate_binary_assets,
)
from studio_core.integrity import classify, content_hash
from scripts.validate_baseline import (
    BaselineValidationError,
    ROOT,
    validate_binary_asset_policy,
    validate_content_integrity,
    validate_instance,
)

#: The shipped control-plane files, copied into every scratch root so the negative cases
#: mutate a copy of the real artifact instead of a paraphrase of it.
REAL_POLICY = (ROOT / "policies/binary-assets.yaml").read_text(encoding="utf-8")
REAL_GITATTRIBUTES = (ROOT / ".gitattributes").read_text(encoding="utf-8")
REAL_MANIFEST_SCHEMA = (ROOT / "contracts/asset-manifest.schema.json").read_text(encoding="utf-8")

TASK_ID = "AST-FIX-0001"
#: A second, unrelated Task Contract. Traceability is a property of one task, so the cross-task
#: cases need two real task ids rather than one task in two states.
OTHER_TASK_ID = "AST-OTHER-0002"
PNG_RELATIVE = "assets/art/table.png"
WEBP_RELATIVE = "assets/art/wheel.webp"

#: A PNG-shaped payload. The NUL byte makes ``studio_core.integrity.classify`` call it binary,
#: and the embedded ``\r\n`` pairs are what a text-normalising hash would silently corrupt.
PNG_BYTES = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRtable\r\nIEND\xaeB`\x82"

#: A WebP-shaped payload. The RIFF length field supplies the NUL bytes.
WEBP_BYTES = b"RIFF\x24\x00\x00\x00WEBPVP8 wheel\r\n\x00chunk"

#: An AWS access key identifier, assembled from fragments. See the module docstring: a literal
#: here would either fail the repository secret scan or force an exemption that also hid real
#: mistakes. The surrounding NUL bytes supply the word boundaries the rule requires.
CREDENTIAL_SAMPLE = b"AKIA" + b"IOSFODNN7EXAMPLE"
CREDENTIAL_RULE_ID = "aws-access-key-id"

#: A Git LFS pointer file, byte for byte as `git lfs` writes one.
LFS_POINTER_BYTES = (
    LFS_POINTER_PREFIX
    + b"\noid sha256:" + b"0" * 64
    + b"\nsize 4096\n"
)


def _require_symlink(link: pathlib.Path, target: pathlib.Path | str) -> None:
    """Create ``link`` or skip: unprivileged Windows accounts cannot make symlinks."""

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - environment dependent
        raise unittest.SkipTest(f"symlinks are unavailable in this environment: {exc}") from exc


class GateFixtureCase(unittest.TestCase):
    """A scratch repository root holding the shipped policy, schema and Git pinning."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        # ``resolve`` matters on Windows, where the temp root can be handed back in 8.3 short
        # form; ``resolve_within`` compares resolved paths and would otherwise see an escape.
        self.base = pathlib.Path(directory.name).resolve()
        self.write_text("policies/binary-assets.yaml", REAL_POLICY)
        self.write_text(".gitattributes", REAL_GITATTRIBUTES)
        self.write_text("contracts/asset-manifest.schema.json", REAL_MANIFEST_SCHEMA)

    # -- fixture construction ------------------------------------------------------------

    def write_text(self, relative: str, text: str) -> pathlib.Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def write_bytes(self, relative: str, data: bytes) -> pathlib.Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_json(self, relative: str, document: Any) -> pathlib.Path:
        return self.write_text(relative, json.dumps(document, indent=2, ensure_ascii=False) + "\n")

    def write_task(
        self,
        assets: Iterable[str] = (PNG_RELATIVE,),
        *,
        status: str = "READY",
        task_id: str = TASK_ID,
    ) -> None:
        """Write the minimal Task Contract shape the gate reads: status and deliverables."""

        self.write_json(
            f"tasks/{task_id}.json",
            {
                "schema_version": "1.0.0",
                "task_id": task_id,
                "status": status,
                "deliverables": [
                    {"name": f"asset-{index}", "artifact_type": "DATASET", "target_uri": f"repo://{relative}"}
                    for index, relative in enumerate(assets)
                ],
            },
        )

    def manifest_entry(
        self,
        relative: str,
        data: bytes,
        *,
        media_type: str = "image/png",
        declared_hash: str | None = None,
        byte_size: int | None = None,
    ) -> dict[str, Any]:
        return {
            "path": relative,
            "media_type": media_type,
            "content_hash": raw_content_hash(data) if declared_hash is None else declared_hash,
            "byte_size": len(data) if byte_size is None else byte_size,
            "source": {"kind": "AI_GENERATED", "created_by": "A-02", "provider": None, "model": None},
            "rights": {
                "license": "internal-only",
                "commercial_use": True,
                "training_permission": "NOT_APPLICABLE",
                "provenance_complete": True,
            },
        }

    def write_manifest(
        self,
        entries: Iterable[dict[str, Any]],
        *,
        task_id: str = TASK_ID,
        filename: str | None = None,
        manifest_id: str = "AM-ASTFIX-0001",
    ) -> pathlib.Path:
        return self.write_json(
            f"assets/manifests/{filename or f'{task_id}-assets.json'}",
            {
                "schema_version": "1.0.0",
                "manifest_id": manifest_id,
                "task_id": task_id,
                "policy_version": "BINARY-ASSETS-001/1.0.0",
                "hash_algorithm": "sha256-raw-bytes",
                "assets": list(entries),
                "created_at": "2026-09-02T00:00:00Z",
            },
        )

    def write_artifact(self, document: dict[str, Any], *, name: str = "AST-FIX-0001-artifact.json") -> None:
        self.write_json(f"artifacts/{name}", document)

    def admitted_png(self, relative: str = PNG_RELATIVE, data: bytes = PNG_BYTES) -> bytes:
        """Write a PNG that satisfies every invariant, and return its bytes."""

        self.write_bytes(relative, data)
        self.write_task([relative])
        self.write_manifest([self.manifest_entry(relative, data)])
        return data

    # -- running the gate ----------------------------------------------------------------

    def report(self) -> BinaryAssetReport:
        return validate_binary_assets(self.base, manifest_validator=validate_instance)

    def codes(self) -> set[str]:
        return {item.code for item in self.report().rejections}

    def rejection(self, code: str) -> BinaryAssetRejection:
        matches = [item for item in self.report().rejections if item.code == code]
        self.assertTrue(matches, f"expected a {code} rejection, found {self.codes()!r}")
        return matches[0]

    def assertRejects(self, code: str) -> BinaryAssetRejection:
        report = self.report()
        self.assertFalse(report.ok)
        return self.rejection(code)


class PolicyDocumentTests(GateFixtureCase):
    """AC-001: the shipped policy is default-deny over an explicit, minimal allowlist."""

    def test_the_shipped_policy_is_default_deny(self) -> None:
        policy = load_policy(ROOT)
        self.assertEqual(policy.mode, "deny_by_default")
        self.assertEqual(policy.policy_version, "BINARY-ASSETS-001/1.0.0")

    def test_the_allowlist_is_exactly_assets_png_and_webp(self) -> None:
        policy = load_policy(ROOT)
        self.assertEqual(policy.allowed_roots, ("assets",))
        self.assertEqual(policy.allowed_extensions, (".png", ".webp"))

    def test_hashing_is_pinned_to_raw_bytes_with_normalisation_prohibited(self) -> None:
        document = yaml.safe_load(REAL_POLICY)
        self.assertEqual(document["hashing"]["algorithm"], "sha256")
        self.assertEqual(document["hashing"]["representation"], "raw_bytes")
        self.assertEqual(document["hashing"]["text_normalization"], "prohibited")
        self.assertEqual(document["hashing"]["prefix"], HASH_PREFIX)

    def test_traceable_status_excludes_draft(self) -> None:
        policy = load_policy(ROOT)
        self.assertNotIn("DRAFT", policy.traceable_task_status)
        self.assertIn("READY", policy.traceable_task_status)

    def test_declaration_sources_cover_the_three_the_gate_reads(self) -> None:
        policy = load_policy(ROOT)
        self.assertEqual(
            policy.declaration_sources,
            frozenset({"artifact_primary", "artifact_component", "asset_manifest"}),
        )

    def test_the_allows_predicate_is_root_and_extension_at_once(self) -> None:
        policy = load_policy(ROOT)
        self.assertTrue(policy.allows("assets/art/table.png"))
        self.assertTrue(policy.allows("assets/deep/nested/wheel.webp"))
        # Case-insensitive on the extension, because a filesystem may hand back either form.
        self.assertTrue(policy.allows("assets/art/TABLE.PNG"))
        # Right extension, wrong root.
        self.assertFalse(policy.allows("docs/art/table.png"))
        # Right root, wrong extension.
        self.assertFalse(policy.allows("assets/art/table.jpg"))
        # A file whose *name* starts with the root is not inside it.
        self.assertFalse(policy.allows("assets.png"))
        self.assertFalse(policy.allows("assets-extra/table.png"))
        # Root matching is case-sensitive: a repository path is not a Windows path.
        self.assertFalse(policy.allows("Assets/art/table.png"))

    # -- negative: a weakened policy must be refused --------------------------------------

    def _rewrite_policy(self, mutate) -> None:
        document = yaml.safe_load(REAL_POLICY)
        mutate(document)
        self.write_text("policies/binary-assets.yaml", yaml.safe_dump(document, allow_unicode=True))

    def test_a_missing_policy_file_is_refused(self) -> None:
        (self.base / "policies/binary-assets.yaml").unlink()
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_MISSING")

    def test_a_non_mapping_policy_is_refused(self) -> None:
        self.write_text("policies/binary-assets.yaml", "- not\n- a\n- mapping\n")
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_a_policy_that_is_not_default_deny_is_refused(self) -> None:
        self._rewrite_policy(lambda document: document.update(mode="allow_by_default"))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_NOT_DEFAULT_DENY")

    def test_a_policy_that_permits_text_normalisation_is_refused(self) -> None:
        # The whole point of a separate binary hash path: if normalisation were allowed, a
        # binary holding CRLF would hash identically to a corrupted LF variant.
        self._rewrite_policy(lambda document: document["hashing"].update(text_normalization="allowed"))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_NORMALISATION_ALLOWED")

    def test_a_policy_that_does_not_hash_raw_bytes_is_refused(self) -> None:
        self._rewrite_policy(lambda document: document["hashing"].update(representation="canonical_text"))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_an_empty_allowlist_is_refused(self) -> None:
        self._rewrite_policy(lambda document: document["allowlist"].update(extensions=[]))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_an_allowlist_root_with_a_separator_is_refused(self) -> None:
        # A root is a single top-level directory name. Accepting "assets/../etc" here would
        # move the escape check into a place that never runs.
        self._rewrite_policy(lambda document: document["allowlist"].update(roots=["assets/../etc"]))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_an_extension_without_a_leading_dot_is_refused(self) -> None:
        self._rewrite_policy(lambda document: document["allowlist"].update(extensions=["png"]))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_a_traceable_status_list_containing_draft_is_refused(self) -> None:
        self._rewrite_policy(
            lambda document: document["traceability"].update(traceable_task_status=["DRAFT", "READY"])
        )
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_a_policy_missing_a_required_section_is_refused(self) -> None:
        self._rewrite_policy(lambda document: document.pop("git_lfs"))
        with self.assertRaises(BinaryAssetError) as caught:
            load_policy(self.base)
        self.assertEqual(caught.exception.code, "POLICY_INVALID")

    def test_the_baseline_step_reports_a_weakened_policy(self) -> None:
        self._rewrite_policy(lambda document: document.update(mode="allow_by_default"))
        with self.assertRaisesRegex(BaselineValidationError, "POLICY_NOT_DEFAULT_DENY"):
            validate_binary_asset_policy(root=self.base)

    def test_the_baseline_step_passes_on_the_shipped_policy(self) -> None:
        summary = validate_binary_asset_policy(root=self.base)
        self.assertEqual(summary["policy_id"], "BINARY-ASSETS-001")
        self.assertEqual(summary["allowed_roots"], ["assets"])
        self.assertEqual(summary["allowed_extensions"], [".png", ".webp"])


class ManifestSchemaTests(GateFixtureCase):
    """AC-004/AC-006: the manifest contract cannot express an undeclared or soft hash."""

    def test_the_manifest_schema_requires_path_hash_and_size(self) -> None:
        schema = json.loads(REAL_MANIFEST_SCHEMA)
        required = schema["$defs"]["assetEntry"]["required"]
        for field in ("path", "content_hash", "byte_size", "media_type", "source", "rights"):
            self.assertIn(field, required)

    def test_the_manifest_schema_pins_the_raw_byte_algorithm(self) -> None:
        schema = json.loads(REAL_MANIFEST_SCHEMA)
        self.assertEqual(schema["properties"]["hash_algorithm"]["const"], "sha256-raw-bytes")

    def test_the_manifest_schema_rejects_an_absolute_or_backslash_path(self) -> None:
        # Defence in depth: the pattern makes these unrepresentable, and the gate rejects
        # them again in ``normalise_declared_path`` before it opens anything.
        schema = json.loads(REAL_MANIFEST_SCHEMA)
        entry_schema = schema["$defs"]["assetEntry"]
        for hostile in ("/etc/shadow.png", "C:/secrets.png", "assets\\art\\table.png"):
            entry = self.manifest_entry(hostile, PNG_BYTES)
            with self.assertRaises(BaselineValidationError):
                validate_instance(entry, entry_schema, root_schema=schema)

    def test_the_baseline_step_requires_the_schema_the_policy_names(self) -> None:
        (self.base / "contracts/asset-manifest.schema.json").unlink()
        with self.assertRaisesRegex(BaselineValidationError, "asset-manifest.schema.json"):
            validate_binary_asset_policy(root=self.base)


class GitattributesCrossCheckTests(GateFixtureCase):
    """AC-002: an allowed extension that Git may line-ending normalise fails validation."""

    def test_the_repository_pins_every_policy_allowed_extension(self) -> None:
        policy = load_policy(ROOT)
        self.assertEqual(unpinned_extensions(policy, REAL_GITATTRIBUTES), ())

    def test_binary_and_minus_text_are_both_accepted_treatments(self) -> None:
        policy = load_policy(self.base)
        self.assertEqual(unpinned_extensions(policy, "*.png -text\n*.webp -text\n"), ())

    def test_a_commented_directive_does_not_pin_an_extension(self) -> None:
        policy = load_policy(self.base)
        self.assertEqual(
            unpinned_extensions(policy, "# *.png binary\n*.webp binary\n"),
            (".png",),
        )

    def test_only_extension_globs_count_as_a_pin(self) -> None:
        parsed = gitattributes_binary_extensions("*.png binary\nassets/logo.webp binary\n* text=auto\n")
        self.assertEqual(parsed, frozenset({".png"}))

    def test_removing_a_directive_fails_the_baseline_step(self) -> None:
        self.write_text(".gitattributes", REAL_GITATTRIBUTES.replace("*.png binary\n", ""))
        with self.assertRaisesRegex(BaselineValidationError, r"\.png"):
            validate_binary_asset_policy(root=self.base)

    def test_removing_a_directive_is_rejected_by_the_gate(self) -> None:
        self.write_text(".gitattributes", REAL_GITATTRIBUTES.replace("*.png binary\n", ""))
        rejection = self.assertRejects("EXTENSION_NOT_PINNED_BINARY")
        self.assertIn(".png", rejection.message)

    def test_a_missing_gitattributes_is_rejected_by_the_gate(self) -> None:
        (self.base / ".gitattributes").unlink()
        self.assertRejects("GITATTRIBUTES_MISSING")

    def test_a_missing_gitattributes_fails_the_baseline_step(self) -> None:
        (self.base / ".gitattributes").unlink()
        with self.assertRaisesRegex(BaselineValidationError, ".gitattributes"):
            validate_binary_asset_policy(root=self.base)


class RawByteHashingTests(unittest.TestCase):
    """AC-005: binary hashing never touches the text normalisation path."""

    def test_the_raw_hash_is_the_untouched_byte_digest(self) -> None:
        import hashlib

        self.assertEqual(raw_content_hash(PNG_BYTES), HASH_PREFIX + hashlib.sha256(PNG_BYTES).hexdigest())

    def test_crlf_and_lf_variants_of_one_binary_stay_distinct(self) -> None:
        collapsed = PNG_BYTES.replace(b"\r\n", b"\n")
        self.assertNotEqual(PNG_BYTES, collapsed)
        self.assertNotEqual(raw_content_hash(PNG_BYTES), raw_content_hash(collapsed))

    def test_the_raw_hash_diverges_from_the_text_hash_exactly_where_it_must(self) -> None:
        # For content the text path calls binary, the two agree -- there is nothing to fold.
        self.assertEqual(classify(PNG_BYTES), "binary")
        self.assertEqual(raw_content_hash(PNG_BYTES), content_hash(PNG_BYTES))
        # For content the text path calls text, the canonical form collapses CRLF and the raw
        # form does not. Routing an asset through the text path is what AC-005 forbids.
        textual = b"pointer\r\ncontent\r\n"
        self.assertEqual(classify(textual), "text")
        self.assertNotEqual(raw_content_hash(textual), content_hash(textual))
        self.assertEqual(content_hash(textual), content_hash(textual.replace(b"\r\n", b"\n")))
        self.assertNotEqual(raw_content_hash(textual), raw_content_hash(textual.replace(b"\r\n", b"\n")))

    def test_raw_hash_file_reads_the_bytes_as_stored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "table.png"
            path.write_bytes(PNG_BYTES)
            self.assertEqual(raw_hash_file(path), raw_content_hash(PNG_BYTES))

    def test_the_declared_hash_shape_is_sha256_lowercase_hex(self) -> None:
        self.assertTrue(is_declared_hash(raw_content_hash(PNG_BYTES)))
        self.assertFalse(is_declared_hash(HASH_PREFIX + "0" * 63))
        self.assertFalse(is_declared_hash(HASH_PREFIX + "A" * 64))
        self.assertFalse(is_declared_hash("sha1:" + "0" * 64))
        self.assertFalse(is_declared_hash("0" * 64))
        self.assertFalse(is_declared_hash(None))


class NormalisationRegressionTests(GateFixtureCase):
    """AC-005: if the gate ever normalised an asset, this pair of tests separates."""

    def test_the_raw_byte_declaration_is_admitted(self) -> None:
        self.admitted_png()
        self.assertEqual(self.report().verified, (PNG_RELATIVE,))

    def test_a_normalised_declaration_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        collapsed = PNG_BYTES.replace(b"\r\n", b"\n")
        self.write_manifest(
            [self.manifest_entry(PNG_RELATIVE, PNG_BYTES, declared_hash=raw_content_hash(collapsed))]
        )
        rejection = self.assertRejects("ASSET_HASH_MISMATCH")
        self.assertIn(raw_content_hash(PNG_BYTES), rejection.message)


class PathSafetyTests(GateFixtureCase):
    """AC-008: symlinks, escapes and absolute paths are refused before any read."""

    def test_normalise_accepts_a_plain_relative_posix_path(self) -> None:
        self.assertEqual(normalise_declared_path("assets/art/table.png"), "assets/art/table.png")

    def test_normalise_refuses_every_hostile_shape(self) -> None:
        cases = {
            "": "ASSET_PATH_EMPTY",
            "   ": "ASSET_PATH_EMPTY",
            "assets\\art\\table.png": "ASSET_PATH_BACKSLASH",
            "assets/art\x00/table.png": "ASSET_PATH_CONTROL_CHARACTER",
            "assets/art\n/table.png": "ASSET_PATH_CONTROL_CHARACTER",
            "/etc/shadow.png": "ASSET_PATH_ABSOLUTE",
            "C:/secrets.png": "ASSET_PATH_ABSOLUTE",
            "//server/share/table.png": "ASSET_PATH_ABSOLUTE",
            "repo://assets/art/table.png": "ASSET_PATH_SCHEME",
            "assets/../../etc/shadow.png": "ASSET_PATH_ESCAPE",
            "../table.png": "ASSET_PATH_ESCAPE",
            "assets/./table.png": "ASSET_PATH_NOT_NORMALISED",
            "assets//table.png": "ASSET_PATH_NOT_NORMALISED",
        }
        for declared, code in cases.items():
            with self.subTest(declared=declared):
                with self.assertRaises(BinaryAssetError) as caught:
                    normalise_declared_path(declared)
                self.assertEqual(caught.exception.code, code)

    def test_normalise_refuses_a_non_string(self) -> None:
        with self.assertRaises(BinaryAssetError) as caught:
            normalise_declared_path(None)
        self.assertEqual(caught.exception.code, "ASSET_PATH_EMPTY")

    def test_resolve_within_returns_the_on_disk_path(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.assertEqual(resolve_within(self.base, PNG_RELATIVE), self.base / PNG_RELATIVE)

    def test_resolve_within_refuses_a_symlinked_file_before_reading_it(self) -> None:
        # The link target does not exist. A ``ASSET_SYMLINK`` verdict therefore proves the
        # refusal happened without an ``open()``: a read would have failed as "missing".
        (self.base / "assets/art").mkdir(parents=True, exist_ok=True)
        _require_symlink(self.base / PNG_RELATIVE, self.base / "assets/art/absent.png")
        with self.assertRaises(BinaryAssetError) as caught:
            resolve_within(self.base, PNG_RELATIVE)
        self.assertEqual(caught.exception.code, "ASSET_SYMLINK")

    def test_resolve_within_refuses_a_symlinked_parent_directory(self) -> None:
        # A symlinked *directory* redirects just as effectively as a symlinked file, so the
        # whole chain from the root down is checked.
        outside = self.base.parent / "outside-assets"
        outside.mkdir(exist_ok=True)
        self.addCleanup(lambda: outside.rmdir() if outside.is_dir() else None)
        (self.base / "assets").mkdir(parents=True, exist_ok=True)
        _require_symlink(self.base / "assets/art", outside)
        with self.assertRaises(BinaryAssetError) as caught:
            resolve_within(self.base, PNG_RELATIVE)
        self.assertEqual(caught.exception.code, "ASSET_SYMLINK")

    def test_a_symlink_under_an_asset_root_is_rejected_by_the_gate(self) -> None:
        self.write_bytes("assets/art/real.png", PNG_BYTES)
        _require_symlink(self.base / PNG_RELATIVE, self.base / "assets/art/real.png")
        rejection = self.assertRejects("ASSET_SYMLINK")
        self.assertIn("assets/art", rejection.path)

    def test_a_dotdot_manifest_entry_is_refused_before_the_file_is_read(self) -> None:
        # ``outside.png`` is never created, so ``ASSET_PATH_ESCAPE`` rather than
        # ``MANIFEST_TARGET_MISSING`` is what proves the ordering AC-008 requires.
        self.admitted_png()
        self.write_manifest(
            [
                self.manifest_entry(PNG_RELATIVE, PNG_BYTES),
                self.manifest_entry("assets/../outside.png", PNG_BYTES),
            ]
        )
        rejection = self.assertRejects("ASSET_PATH_ESCAPE")
        self.assertEqual(rejection.path, "assets/../outside.png")
        self.assertFalse((self.base.parent / "outside.png").exists())

    def test_an_absolute_manifest_entry_never_reaches_the_filesystem(self) -> None:
        # The schema pattern already makes this unrepresentable, so the manifest is refused
        # whole rather than entry by entry. Either way nothing is opened.
        self.admitted_png()
        self.write_manifest([self.manifest_entry("/etc/shadow.png", PNG_BYTES)])
        self.assertIn("MANIFEST_SCHEMA_INVALID", self.codes())


class LfsPointerTests(GateFixtureCase):
    """AC-010: a Git LFS pointer standing in for an asset is a substitution, not an asset."""

    def test_pointer_bytes_are_recognised(self) -> None:
        self.assertTrue(is_lfs_pointer(LFS_POINTER_BYTES))
        self.assertFalse(is_lfs_pointer(PNG_BYTES))

    def test_leading_whitespace_does_not_hide_a_pointer(self) -> None:
        self.assertTrue(is_lfs_pointer(b"\r\n \t" + LFS_POINTER_BYTES))

    def test_a_pointer_substituted_for_an_asset_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, LFS_POINTER_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)])
        self.assertRejects("ASSET_LFS_POINTER")

    def test_the_pointers_own_hash_cannot_satisfy_the_asset_declaration(self) -> None:
        # The attack this closes: swap the PNG for its pointer, then re-declare the manifest
        # hash over the pointer's bytes so the hash check passes. The pointer is refused on
        # its content, before any declaration is consulted.
        self.write_bytes(PNG_RELATIVE, LFS_POINTER_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, LFS_POINTER_BYTES)])
        report = self.report()
        self.assertFalse(report.ok)
        self.assertEqual({item.code for item in report.rejections}, {"ASSET_LFS_POINTER"})
        self.assertEqual(report.verified, ())

    def test_a_pointer_is_reachable_even_though_it_classifies_as_text(self) -> None:
        # A pointer holds no NUL byte, so the binary classification alone would never see it.
        # The gate also walks the allowed asset roots, which is what makes AC-010 enforceable.
        self.assertEqual(classify(LFS_POINTER_BYTES), "text")
        self.write_bytes(PNG_RELATIVE, LFS_POINTER_BYTES)
        self.assertEqual(iter_binary_files(self.base), ())
        self.assertEqual(allowlisted_files(self.base, load_policy(self.base)), (PNG_RELATIVE,))


class CredentialBytesTests(GateFixtureCase):
    """AC-009: an allowlisted path and extension do not exempt an asset from the secret scan."""

    def _payload(self, extra: bytes = b"") -> bytes:
        return PNG_BYTES + b"\x00" + extra + CREDENTIAL_SAMPLE + b"\x00tail"

    def test_the_scan_rules_apply_to_raw_binary_bytes(self) -> None:
        self.assertIn(CREDENTIAL_RULE_ID, credential_rule_ids(self._payload()))
        self.assertEqual(credential_rule_ids(PNG_BYTES), ())

    def test_the_rule_set_is_the_repository_secret_scan_rule_set(self) -> None:
        self.assertEqual(
            {rule.rule_id for rule in secret_scan.RULES},
            {"anthropic-api-key", "openai-style-api-key", "github-token", "github-fine-grained-token",
             "slack-token", "aws-access-key-id", "google-api-key", "private-key-block",
             "bearer-token", "assigned-credential", "json-web-token"},
        )

    def test_a_fully_traced_asset_with_credential_bytes_is_still_rejected(self) -> None:
        payload = self._payload()
        self.admitted_png(data=payload)
        rejection = self.assertRejects("ASSET_CREDENTIAL_LIKE")
        self.assertIn(CREDENTIAL_RULE_ID, rejection.message)

    def test_the_rejection_names_the_rule_and_never_the_matched_bytes(self) -> None:
        payload = self._payload()
        self.admitted_png(data=payload)
        rejection = self.rejection("ASSET_CREDENTIAL_LIKE")
        self.assertNotIn(CREDENTIAL_SAMPLE.decode("ascii"), rejection.message)

    def test_an_in_band_allow_marker_cannot_exempt_a_binary(self) -> None:
        # ``secret_scan.scan_text`` honours the marker; a binary that could exempt itself by
        # embedding a comment string would not be scanned at all, so the gate ignores it.
        payload = self._payload(extra=secret_scan.ALLOW_MARKER.encode("ascii") + b"\n")
        self.admitted_png(data=payload)
        self.assertRejects("ASSET_CREDENTIAL_LIKE")


class TaskTraceabilityTests(GateFixtureCase):
    """AC-003: an asset no open Task Contract claims is not an auditable artifact."""

    def test_a_ready_task_deliverable_traces_the_asset(self) -> None:
        self.admitted_png()
        report = self.report()
        self.assertTrue(report.ok)
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    def test_every_traceable_status_admits_the_asset(self) -> None:
        policy = load_policy(self.base)
        for status in sorted(policy.traceable_task_status):
            with self.subTest(status=status):
                self.admitted_png()
                self.write_task([PNG_RELATIVE], status=status)
                self.assertTrue(self.report().ok, self.codes())

    def test_an_asset_no_task_declares_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)])
        self.assertRejects("ASSET_UNTRACKED_BY_TASK")

    def test_a_draft_task_does_not_trace_an_asset(self) -> None:
        self.admitted_png()
        self.write_task([PNG_RELATIVE], status="DRAFT")
        self.assertRejects("ASSET_UNTRACKED_BY_TASK")

    def test_a_task_deliverable_naming_a_different_asset_does_not_trace_this_one(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([WEBP_RELATIVE])
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)])
        rejection = self.assertRejects("ASSET_UNTRACKED_BY_TASK")
        self.assertEqual(rejection.path, PNG_RELATIVE)

    def test_collect_declarations_indexes_the_deliverable(self) -> None:
        self.admitted_png()
        index = collect_declarations(self.base, load_policy(self.base), manifest_validator=validate_instance)
        sources = {item.source for item in index.for_path(PNG_RELATIVE)}
        self.assertEqual(sources, {"task-deliverable", "asset-manifest"})
        self.assertEqual(index.manifests, (f"assets/manifests/{TASK_ID}-assets.json",))


class HashDeclarationTests(GateFixtureCase):
    """AC-004/AC-006/AC-007: a declared raw-byte hash must exist and must match."""

    def test_an_asset_manifest_declaration_admits_the_asset(self) -> None:
        self.admitted_png()
        self.assertTrue(self.report().ok, self.codes())

    def test_an_artifact_primary_hash_admits_the_asset(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTFIX-0001",
                "task_id": TASK_ID,
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": raw_content_hash(PNG_BYTES),
            }
        )
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    def test_an_artifact_component_hash_admits_the_asset(self) -> None:
        # The ``X`` / ``X_hash`` pair convention the R2 artifact already uses.
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTFIX-0002",
                "task_id": TASK_ID,
                "uri": "repo://docs/operations/whatever.md",
                "content_hash": HASH_PREFIX + "1" * 64,
                "specification": {
                    "table_image": PNG_RELATIVE,
                    "table_image_hash": raw_content_hash(PNG_BYTES),
                },
            }
        )
        self.assertTrue(self.report().ok, self.codes())

    def test_a_traced_asset_with_no_declaration_anywhere_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        rejection = self.assertRejects("ASSET_HASH_UNDECLARED")
        self.assertIn("assets/manifests", rejection.message)

    def test_a_missing_manifest_is_not_a_pass(self) -> None:
        self.admitted_png()
        (self.base / f"assets/manifests/{TASK_ID}-assets.json").unlink()
        self.assertRejects("ASSET_HASH_UNDECLARED")

    def test_a_manifest_without_this_asset_entry_is_not_a_pass(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_bytes(WEBP_RELATIVE, WEBP_BYTES)
        self.write_task([PNG_RELATIVE, WEBP_RELATIVE])
        self.write_manifest([self.manifest_entry(WEBP_RELATIVE, WEBP_BYTES, media_type="image/webp")])
        report = self.report()
        self.assertEqual([item.code for item in report.rejections], ["ASSET_HASH_UNDECLARED"])
        self.assertEqual(report.rejections[0].path, PNG_RELATIVE)
        self.assertEqual(report.verified, (WEBP_RELATIVE,))

    def test_a_manifest_entry_missing_its_hash_field_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        entry = self.manifest_entry(PNG_RELATIVE, PNG_BYTES)
        entry.pop("content_hash")
        self.write_manifest([entry])
        codes = self.codes()
        self.assertIn("MANIFEST_SCHEMA_INVALID", codes)
        self.assertIn("ASSET_HASH_UNDECLARED", codes)

    def test_a_one_byte_change_is_rejected_with_both_digests(self) -> None:
        tampered = PNG_BYTES[:-1] + bytes([PNG_BYTES[-1] ^ 0x01])
        self.write_bytes(PNG_RELATIVE, tampered)
        self.write_task([PNG_RELATIVE])
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)])
        rejection = self.assertRejects("ASSET_HASH_MISMATCH")
        self.assertIn(PNG_RELATIVE, rejection.message)
        self.assertIn(raw_content_hash(PNG_BYTES), rejection.message)
        self.assertIn(raw_content_hash(tampered), rejection.message)

    def test_a_malformed_declared_hash_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTFIX-0003",
                "task_id": TASK_ID,
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": "sha256:not-a-digest",
            }
        )
        rejection = self.assertRejects("ASSET_HASH_MALFORMED")
        self.assertIn("64 lowercase hex", rejection.message)

    def test_a_byte_size_that_disagrees_with_the_file_is_rejected(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_manifest(
            [self.manifest_entry(PNG_RELATIVE, PNG_BYTES, byte_size=len(PNG_BYTES) + 1)]
        )
        rejection = self.assertRejects("ASSET_SIZE_MISMATCH")
        self.assertIn(str(len(PNG_BYTES)), rejection.message)

    def test_a_manifest_filename_that_does_not_match_its_task_is_rejected(self) -> None:
        self.admitted_png()
        (self.base / f"assets/manifests/{TASK_ID}-assets.json").unlink()
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)], filename="wrong-name.json")
        rejection = self.assertRejects("MANIFEST_FILENAME_MISMATCH")
        self.assertIn(f"{TASK_ID}-assets.json", rejection.message)

    def test_a_manifest_declaring_a_file_that_does_not_exist_is_rejected(self) -> None:
        self.admitted_png()
        self.write_manifest(
            [
                self.manifest_entry(PNG_RELATIVE, PNG_BYTES),
                self.manifest_entry("assets/art/absent.png", PNG_BYTES),
            ]
        )
        rejection = self.assertRejects("MANIFEST_TARGET_MISSING")
        self.assertEqual(rejection.path, "assets/art/absent.png")

    def test_a_manifest_entry_outside_the_allowlist_is_rejected(self) -> None:
        self.admitted_png()
        self.write_bytes("docs/table.png", PNG_BYTES)
        self.write_manifest(
            [
                self.manifest_entry(PNG_RELATIVE, PNG_BYTES),
                self.manifest_entry("docs/table.png", PNG_BYTES),
            ]
        )
        self.assertIn("ASSET_NOT_ALLOWLISTED", self.codes())

    def test_unreadable_manifest_json_is_rejected(self) -> None:
        self.admitted_png()
        self.write_text(f"assets/manifests/{TASK_ID}-assets.json", "{not json")
        self.assertRejects("MANIFEST_UNREADABLE")

    def test_a_schema_invalid_manifest_is_rejected_rather_than_ignored(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_json(
            f"assets/manifests/{TASK_ID}-assets.json",
            {"schema_version": "1.0.0", "task_id": TASK_ID, "assets": []},
        )
        self.assertRejects("MANIFEST_SCHEMA_INVALID")

    def test_a_missing_manifest_schema_is_rejected(self) -> None:
        self.admitted_png()
        (self.base / "contracts/asset-manifest.schema.json").unlink()
        self.assertRejects("MANIFEST_SCHEMA_MISSING")


class CrossTaskDeclarationTests(GateFixtureCase):
    """AC-003/AC-004: the deliverable and the hash must be declared by the *same* task.

    The defect these tests pin: the traceability check and the hash check used to be two
    independent existence questions over one path. "Some open task names this asset" and "some
    declaration carries a matching hash" were both true when task A named the deliverable and
    an unrelated task B supplied the hash -- so an asset passed although no single task ever
    asserted both halves, and the audit trail led nowhere.

    The rule cuts both ways, and both directions are tested here: a foreign task cannot admit
    an asset, and a foreign task cannot reject one either. Otherwise anyone able to add a
    manifest could invalidate another task's correctly declared asset by declaring a wrong hash
    for it.
    """

    def _spoofing_manifest(self, *, declared_hash: str | None = None) -> None:
        """Write a schema-valid manifest for a task that does not own ``PNG_RELATIVE``."""

        self.write_manifest(
            [self.manifest_entry(PNG_RELATIVE, PNG_BYTES, declared_hash=declared_hash)],
            task_id=OTHER_TASK_ID,
            manifest_id="AM-ASTOTHER-0002",
        )

    # -- a foreign declaration must not admit ---------------------------------------------

    def test_a_manifest_belonging_to_another_task_does_not_admit_the_asset(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])                       # task A owns the deliverable
        self.write_task([WEBP_RELATIVE], task_id=OTHER_TASK_ID)  # task B owns something else
        self._spoofing_manifest()                              # ...but declares A's hash
        report = self.report()
        self.assertFalse(report.ok)
        self.assertEqual(report.verified, ())
        rejection = self.rejection("ASSET_HASH_CROSS_TASK")
        self.assertEqual(rejection.path, PNG_RELATIVE)
        self.assertIn(OTHER_TASK_ID, rejection.message)
        self.assertIn(TASK_ID, rejection.message)

    def test_an_artifact_primary_hash_from_another_task_does_not_admit_the_asset(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTOTHER-0001",
                "task_id": OTHER_TASK_ID,
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": raw_content_hash(PNG_BYTES),
            }
        )
        self.assertRejects("ASSET_HASH_CROSS_TASK")
        self.assertEqual(self.report().verified, ())

    def test_an_artifact_component_hash_from_another_task_does_not_admit_the_asset(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTOTHER-0002",
                "task_id": OTHER_TASK_ID,
                "uri": "repo://docs/operations/whatever.md",
                "content_hash": HASH_PREFIX + "1" * 64,
                "specification": {
                    "table_image": PNG_RELATIVE,
                    "table_image_hash": raw_content_hash(PNG_BYTES),
                },
            }
        )
        self.assertRejects("ASSET_HASH_CROSS_TASK")

    def test_an_artifact_without_a_task_id_cannot_declare_the_hash(self) -> None:
        # A declaration that names no task cannot be bound to a deliverable, so it is not
        # evidence that any task checked these bytes.
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTFIX-0004",
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": raw_content_hash(PNG_BYTES),
            }
        )
        self.assertRejects("ASSET_HASH_CROSS_TASK")

    def test_a_draft_task_manifest_cannot_supply_the_hash_for_a_ready_task_asset(self) -> None:
        # Task B is not traceable at all, so its manifest is exactly a foreign declaration.
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_task([PNG_RELATIVE], status="DRAFT", task_id=OTHER_TASK_ID)
        self._spoofing_manifest()
        self.assertRejects("ASSET_HASH_CROSS_TASK")

    def test_a_foreign_correct_hash_cannot_rescue_a_same_task_mismatch(self) -> None:
        # Task A declares the wrong hash; task B declares the right one. The asset is refused
        # on A's mismatch -- B's declaration is not consulted in either direction.
        tampered = PNG_BYTES[:-1] + bytes([PNG_BYTES[-1] ^ 0x01])
        self.write_bytes(PNG_RELATIVE, tampered)
        self.write_task([PNG_RELATIVE])
        self.write_manifest([self.manifest_entry(PNG_RELATIVE, PNG_BYTES)])
        self._spoofing_manifest(declared_hash=raw_content_hash(tampered))
        rejection = self.assertRejects("ASSET_HASH_MISMATCH")
        self.assertIn(f"{TASK_ID}-assets.json", rejection.message)
        self.assertNotIn(f"{OTHER_TASK_ID}-assets.json", rejection.message)

    # -- a foreign declaration must not reject either ---------------------------------------

    def test_a_foreign_wrong_manifest_hash_does_not_poison_a_correctly_traced_asset(self) -> None:
        self.admitted_png()
        self._spoofing_manifest(declared_hash=HASH_PREFIX + "b" * 64)
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    def test_a_foreign_wrong_artifact_hash_does_not_poison_a_correctly_traced_asset(self) -> None:
        self.admitted_png()
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTOTHER-0003",
                "task_id": OTHER_TASK_ID,
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": HASH_PREFIX + "c" * 64,
            }
        )
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    def test_a_foreign_wrong_byte_size_does_not_poison_a_correctly_traced_asset(self) -> None:
        self.admitted_png()
        self.write_manifest(
            [self.manifest_entry(PNG_RELATIVE, PNG_BYTES, byte_size=len(PNG_BYTES) + 99)],
            task_id=OTHER_TASK_ID,
            manifest_id="AM-ASTOTHER-0002",
        )
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    # -- the valid same-task path ------------------------------------------------------------

    def test_one_task_declaring_both_the_deliverable_and_the_hash_is_admitted(self) -> None:
        self.admitted_png()
        index = collect_declarations(self.base, load_policy(self.base), manifest_validator=validate_instance)
        declarations = index.for_path(PNG_RELATIVE)
        self.assertEqual({item.task_id for item in declarations}, {TASK_ID})
        self.assertEqual({item.source for item in declarations}, {"task-deliverable", "asset-manifest"})
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))

    def test_an_artifact_admits_the_asset_only_when_it_names_the_declaring_task(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_artifact(
            {
                "schema_version": "1.0.0",
                "artifact_id": "ART-ASTFIX-0005",
                "task_id": TASK_ID,
                "uri": f"repo://{PNG_RELATIVE}",
                "content_hash": raw_content_hash(PNG_BYTES),
            }
        )
        self.assertTrue(self.report().ok, self.codes())

    def test_either_of_two_tasks_claiming_the_deliverable_may_declare_the_hash(self) -> None:
        # Eligibility is per declaration, not "the first task found": if two traceable tasks
        # both claim the asset, a hash from either one is a same-task declaration.
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_task([PNG_RELATIVE])
        self.write_task([PNG_RELATIVE], task_id=OTHER_TASK_ID)
        self._spoofing_manifest()
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE,))


class AllowlistBoundaryTests(GateFixtureCase):
    """AC-001: default-deny means the allowlist is the only way in."""

    def test_a_binary_outside_the_allowed_roots_is_rejected(self) -> None:
        self.write_bytes("docs/diagrams/flow.png", PNG_BYTES)
        rejection = self.assertRejects("ASSET_NOT_ALLOWLISTED")
        self.assertEqual(rejection.path, "docs/diagrams/flow.png")
        self.assertIn("default-deny", rejection.message)

    def test_a_disallowed_extension_under_an_allowed_root_is_rejected(self) -> None:
        self.write_bytes("assets/art/table.jpg", PNG_BYTES)
        self.write_task(["assets/art/table.jpg"])
        rejection = self.assertRejects("ASSET_NOT_ALLOWLISTED")
        self.assertEqual(rejection.path, "assets/art/table.jpg")
        self.assertIn(".webp", rejection.message)

    def test_a_binary_at_the_repository_root_is_rejected(self) -> None:
        self.write_bytes("table.png", PNG_BYTES)
        self.assertRejects("ASSET_NOT_ALLOWLISTED")

    def test_both_allowed_extensions_are_admitted_together(self) -> None:
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.write_bytes(WEBP_RELATIVE, WEBP_BYTES)
        self.write_task([PNG_RELATIVE, WEBP_RELATIVE])
        self.write_manifest(
            [
                self.manifest_entry(PNG_RELATIVE, PNG_BYTES),
                self.manifest_entry(WEBP_RELATIVE, WEBP_BYTES, media_type="image/webp"),
            ]
        )
        report = self.report()
        self.assertTrue(report.ok, self.codes())
        self.assertEqual(report.verified, (PNG_RELATIVE, WEBP_RELATIVE))
        self.assertEqual(report.count, 2)

    def test_evaluate_asset_reports_a_declared_but_absent_file(self) -> None:
        policy = load_policy(self.base)
        index = collect_declarations(self.base, policy, manifest_validator=validate_instance)
        rejection = evaluate_asset(self.base, PNG_RELATIVE, index, policy)
        self.assertIsNotNone(rejection)
        self.assertEqual(rejection.code, "ASSET_MISSING")


class DiscoveryTests(GateFixtureCase):
    """What the walk sees, and what it deliberately does not."""

    def test_iter_binary_files_finds_binaries_anywhere_on_the_committed_surface(self) -> None:
        self.write_bytes("docs/diagrams/flow.png", PNG_BYTES)
        self.write_bytes(PNG_RELATIVE, PNG_BYTES)
        self.assertEqual(iter_binary_files(self.base), ("assets/art/table.png", "docs/diagrams/flow.png"))

    def test_iter_binary_files_skips_caches_and_scratch_worktrees(self) -> None:
        self.write_bytes("__pycache__/module.pyc", PNG_BYTES)
        self.write_bytes("node_modules/pkg/blob.bin", PNG_BYTES)
        self.write_bytes(".claude/worktrees/review/assets/art/table.png", PNG_BYTES)
        self.assertEqual(iter_binary_files(self.base), ())

    def test_select_binary_files_ignores_symlinks(self) -> None:
        # Classifying a symlink would already have followed it, which is exactly the read the
        # pre-read refusal exists to prevent.
        target = self.write_bytes("assets/art/real.png", PNG_BYTES)
        _require_symlink(self.base / PNG_RELATIVE, target)
        found = select_binary_files(self.base, [self.base / PNG_RELATIVE, target])
        self.assertEqual(found, ("assets/art/real.png",))

    def test_ambiguous_encoding_is_left_to_the_text_integrity_path(self) -> None:
        # No NUL byte and not UTF-8. ``studio_core.integrity`` fails that closed; the gate
        # must not swallow the file as an admitted binary or crash on it.
        self.write_bytes("docs/latin1.txt", b"\xff\xfe caf\xe9\r\n")
        self.assertEqual(select_binary_files(self.base, [self.base / "docs/latin1.txt"]), ())

    def test_allowlisted_files_covers_paths_the_classifier_calls_text(self) -> None:
        self.write_bytes(PNG_RELATIVE, b"not actually binary\n")
        self.assertEqual(allowlisted_files(self.base, load_policy(self.base)), (PNG_RELATIVE,))


class ReportContractTests(GateFixtureCase):
    """AC-013: the report exposes the verified binaries without weakening anything."""

    def test_an_empty_tree_is_a_passing_report(self) -> None:
        report = self.report()
        self.assertTrue(report.ok)
        self.assertEqual(report.count, 0)
        self.assertEqual(report.verified, ())
        self.assertEqual(report.rejections, ())

    def test_to_dict_publishes_the_policy_the_allowlist_and_the_paths(self) -> None:
        self.admitted_png()
        payload = self.report().to_dict()
        self.assertEqual(
            set(payload),
            {"policy_id", "policy_version", "allowed_roots", "allowed_extensions", "count",
             "verified", "manifests", "rejections"},
        )
        self.assertEqual(payload["verified"], [PNG_RELATIVE])
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["policy_version"], "BINARY-ASSETS-001/1.0.0")
        self.assertEqual(payload["manifests"], [f"assets/manifests/{TASK_ID}-assets.json"])

    def test_ok_is_false_as_soon_as_anything_is_refused(self) -> None:
        self.write_bytes("docs/diagrams/flow.png", PNG_BYTES)
        report = self.report()
        self.assertFalse(report.ok)
        self.assertEqual(report.verified, ())

    def test_format_rejections_names_the_code_and_the_reason(self) -> None:
        rendered = format_rejections(
            [BinaryAssetRejection("assets/art/table.png", "ASSET_HASH_MISMATCH", "declared vs actual")]
        )
        self.assertEqual(rendered, "[ASSET_HASH_MISMATCH] declared vs actual")

    def test_a_caller_supplied_binary_list_is_honoured(self) -> None:
        # ``validate_content_integrity`` classifies the tree once and hands the result over.
        self.write_bytes("docs/diagrams/flow.png", PNG_BYTES)
        report = validate_binary_assets(self.base, ["docs/diagrams/flow.png"], manifest_validator=validate_instance)
        self.assertEqual([item.code for item in report.rejections], ["ASSET_NOT_ALLOWLISTED"])


class RepositoryStateTests(unittest.TestCase):
    """AC-011/AC-014: the gate holds over the real repository, and adds no binary to it."""

    def test_the_repository_admits_every_binary_it_holds(self) -> None:
        report = validate_binary_assets(ROOT, manifest_validator=validate_instance)
        self.assertTrue(report.ok, format_rejections(report.rejections))
        self.assertEqual(report.count, len(report.verified))

    def test_content_integrity_publishes_the_gate_report(self) -> None:
        gate = validate_content_integrity()["binary_assets"]
        self.assertEqual(gate["rejections"], [])
        self.assertEqual(gate["policy_version"], "BINARY-ASSETS-001/1.0.0")
        self.assertEqual(gate["allowed_extensions"], [".png", ".webp"])

    def test_the_policy_and_the_gate_agree_about_the_repository(self) -> None:
        summary = validate_binary_asset_policy()
        report = validate_binary_assets(ROOT, manifest_validator=validate_instance)
        self.assertEqual(summary["allowed_roots"], list(report.allowed_roots))
        self.assertEqual(summary["policy_version"], report.policy_version)

    def test_this_task_leaves_no_untracked_binary_behind(self) -> None:
        # AC-014 states the negative fixtures must live in a temporary directory and never
        # become committable bytes. Rather than pinning a count, this asserts the property:
        # nothing Git does not already track classifies as a binary.
        try:
            output = subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=all"],
                cwd=ROOT,
                capture_output=True,
                check=True,
                text=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - env dependent
            self.skipTest(f"git is unavailable in this environment: {exc}")
        untracked = [line[3:] for line in output.splitlines() if line.startswith("?? ")]
        offenders = [
            relative
            for relative in untracked
            if (ROOT / relative).is_file() and (ROOT / relative).read_bytes()[:8000].find(b"\x00") != -1
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
