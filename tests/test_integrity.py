"""Regression suite for cross-platform artifact content hashing.

The defect this suite exists to prevent: an Artifact Contract binds a ``content_hash`` to a
``repo://`` path, the validator hashed the bytes as they sat on disk, and a Windows checkout
with ``core.autocrlf=true`` materialised the same Git blob with CRLF endings. The integrity
check then reported tampering against a file nobody had touched. The fix must hold both
directions at once, so every test here is paired: line endings must not change the digest,
and content must.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from studio_core.integrity import (
    BINARY_SNIFF_BYTES,
    HASH_PREFIX,
    IntegrityError,
    canonical_bytes,
    classify,
    content_hash,
    hash_file,
    verify_file,
)
from scripts.validate_baseline import (
    BaselineValidationError,
    ROOT,
    hashed_content_references,
    load_json,
    repository_files,
    validate_content_integrity,
)

#: A text body with every feature that makes line-ending handling subtle: a bare CR that is
#: not part of a CRLF pair, a blank line, a trailing newline, and non-ASCII characters whose
#: UTF-8 encoding must survive normalisation untouched.
SAMPLE_TEXT_LF = "# 계약\nfirst\n\nsecond\rmid\nthird\n"


def _as_crlf(text: str) -> bytes:
    return text.replace("\n", "\r\n").encode("utf-8")


def _as_lf(text: str) -> bytes:
    return text.encode("utf-8")


class LineEndingEquivalenceTests(unittest.TestCase):
    """LF and CRLF renderings of the same text are the same artifact."""

    def test_lf_and_crlf_bytes_produce_the_same_hash(self) -> None:
        self.assertNotEqual(_as_lf(SAMPLE_TEXT_LF), _as_crlf(SAMPLE_TEXT_LF))
        self.assertEqual(content_hash(_as_lf(SAMPLE_TEXT_LF)), content_hash(_as_crlf(SAMPLE_TEXT_LF)))

    def test_the_canonical_form_is_the_lf_form(self) -> None:
        # Consistency with Git blobs is the whole point: the digest must be the one a Linux
        # checkout computes over the raw file, not a third representation of our own.
        expected = HASH_PREFIX + hashlib.sha256(_as_lf(SAMPLE_TEXT_LF)).hexdigest()
        self.assertEqual(content_hash(_as_crlf(SAMPLE_TEXT_LF)), expected)
        self.assertEqual(content_hash(_as_lf(SAMPLE_TEXT_LF)), expected)

    def test_a_bare_cr_is_preserved_exactly_as_git_preserves_it(self) -> None:
        # Git's text=auto conversion rewrites CRLF pairs only. Collapsing a lone CR would
        # make two genuinely different files hash alike.
        with_cr = b"alpha\rbeta\n"
        without_cr = b"alpha\nbeta\n"
        self.assertEqual(canonical_bytes(with_cr), with_cr)
        self.assertNotEqual(content_hash(with_cr), content_hash(without_cr))

    def test_mixed_endings_in_one_file_normalise_to_a_single_form(self) -> None:
        mixed = b"one\r\ntwo\nthree\r\n"
        self.assertEqual(content_hash(mixed), content_hash(b"one\ntwo\nthree\n"))

    def test_a_file_hashes_the_same_from_either_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            lf_path = base / "lf.yaml"
            crlf_path = base / "crlf.yaml"
            lf_path.write_bytes(_as_lf(SAMPLE_TEXT_LF))
            crlf_path.write_bytes(_as_crlf(SAMPLE_TEXT_LF))
            self.assertEqual(hash_file(lf_path), hash_file(crlf_path))
            digest = hash_file(lf_path)
            self.assertTrue(verify_file(crlf_path, digest).matches)
            self.assertTrue(verify_file(lf_path, digest).matches)


class TamperRejectionTests(unittest.TestCase):
    """Line-ending tolerance must not become tolerance for edited content."""

    def _digest(self) -> str:
        return content_hash(_as_lf(SAMPLE_TEXT_LF))

    def test_an_edited_character_changes_the_hash(self) -> None:
        tampered = SAMPLE_TEXT_LF.replace("first", "f1rst")
        self.assertNotEqual(content_hash(_as_lf(tampered)), self._digest())
        self.assertNotEqual(content_hash(_as_crlf(tampered)), self._digest())

    def test_appended_content_changes_the_hash(self) -> None:
        self.assertNotEqual(content_hash(_as_lf(SAMPLE_TEXT_LF + "appended\n")), self._digest())

    def test_removed_content_changes_the_hash(self) -> None:
        self.assertNotEqual(content_hash(_as_lf(SAMPLE_TEXT_LF.replace("second\rmid\n", ""))), self._digest())

    def test_reordered_lines_change_the_hash(self) -> None:
        reordered = "# 계약\nsecond\rmid\n\nfirst\nthird\n"
        self.assertNotEqual(content_hash(_as_lf(reordered)), self._digest())

    def test_an_added_blank_line_changes_the_hash_in_both_encodings(self) -> None:
        # A blank line is the closest an edit gets to being pure whitespace, so it is the
        # case most likely to be swallowed by an over-eager normaliser.
        tampered = SAMPLE_TEXT_LF + "\n"
        self.assertNotEqual(content_hash(_as_lf(tampered)), self._digest())
        self.assertNotEqual(content_hash(_as_crlf(tampered)), self._digest())

    def test_verify_file_reports_a_mismatch_with_both_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "tampered.md"
            path.write_bytes(_as_crlf(SAMPLE_TEXT_LF + "appended\n"))
            decision = verify_file(path, self._digest(), label="tampered.md")
            self.assertFalse(decision.matches)
            self.assertEqual(decision.expected, self._digest())
            self.assertNotEqual(decision.actual, self._digest())
            self.assertIn("tampered.md", decision.message)


class BinaryContentTests(unittest.TestCase):
    """Binary artifacts must be hashed byte for byte."""

    #: A NUL byte followed by bytes that look like a CRLF pair. Normalising this would corrupt
    #: the payload and make two different binaries hash alike.
    BINARY_CRLF = b"\x89PNG\x00\r\ndata\r\n"
    BINARY_LF = b"\x89PNG\x00\ndata\n"

    def test_binary_content_is_classified_by_a_nul_byte(self) -> None:
        self.assertEqual(classify(self.BINARY_CRLF), "binary")
        self.assertEqual(classify(_as_lf(SAMPLE_TEXT_LF)), "text")

    def test_binary_bytes_are_never_normalised(self) -> None:
        self.assertEqual(canonical_bytes(self.BINARY_CRLF), self.BINARY_CRLF)
        expected = HASH_PREFIX + hashlib.sha256(self.BINARY_CRLF).hexdigest()
        self.assertEqual(content_hash(self.BINARY_CRLF), expected)

    def test_binary_variants_that_differ_only_in_crlf_stay_distinct(self) -> None:
        self.assertNotEqual(content_hash(self.BINARY_CRLF), content_hash(self.BINARY_LF))

    def test_a_nul_beyond_the_sniff_window_is_treated_as_text(self) -> None:
        # This is Git's rule, and matching it is what keeps our digest equal to the blob's.
        payload = b"a" * BINARY_SNIFF_BYTES + b"\r\n\x00"
        self.assertEqual(classify(payload), "text")
        self.assertEqual(content_hash(payload), content_hash(b"a" * BINARY_SNIFF_BYTES + b"\n\x00"))

    def test_ambiguous_content_is_rejected_rather_than_guessed(self) -> None:
        # No NUL byte, so Git would call it text and normalise it, but it is not UTF-8 and we
        # cannot reproduce that normalisation with confidence. Failing closed beats a silent
        # disagreement with the blob.
        with self.assertRaisesRegex(IntegrityError, "ambiguous"):
            classify(b"\xff\xfe caf\xe9\r\n", label="latin1.txt")
        with self.assertRaises(IntegrityError):
            content_hash(b"\xff\xfe caf\xe9\r\n")


class GitBlobConsistencyTests(unittest.TestCase):
    """The canonical digest must equal the digest of the blob Git actually stores."""

    def test_the_canonical_hash_matches_git_hash_object_for_tracked_text(self) -> None:
        relative = "operations/collaboration.yaml"
        try:
            blob = subprocess.run(
                ["git", "show", f"HEAD:{relative}"],
                cwd=ROOT,
                capture_output=True,
                check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - env dependent
            self.skipTest(f"git is unavailable in this environment: {exc}")
        # `git show` emits the blob verbatim, so this is the byte string Git stored.
        self.assertEqual(hash_file(ROOT / relative), HASH_PREFIX + hashlib.sha256(blob).hexdigest())

    def test_gitattributes_pins_the_text_normalisation_git_must_apply(self) -> None:
        text = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        directives = [line.split("#", 1)[0].split() for line in text.splitlines()]
        self.assertTrue(any(f and f[0] == "*" and "text=auto" in f[1:] for f in directives))


class ContentIntegrityValidatorTests(unittest.TestCase):
    """The baseline step over the real repository, and the failures it must produce."""

    def test_the_repository_passes_content_integrity(self) -> None:
        report = validate_content_integrity()
        self.assertTrue(report["verified"])
        self.assertGreater(report["files"]["text"], 0)

    def test_binary_admission_is_an_invariant_rather_than_a_count(self) -> None:
        # This replaces the equality assertion that pinned the classified binary count to
        # zero. That assertion was not an integrity property: it would reject the first
        # legitimate PNG traced through a READY task, an Artifact Contract and a raw-byte
        # SHA-256, and relaxing it to any other number would admit binaries nobody declared.
        # The property that actually holds is that every binary the walk classified was
        # admitted by the default-deny gate. The removed expression is deliberately not
        # quoted here: ``test_the_hardcoded_zero_binary_assertion_is_gone`` greps this file
        # for it, so spelling it out in prose would make the guard fail on its own comment.
        report = validate_content_integrity()
        gate = report["binary_assets"]
        self.assertEqual(gate["rejections"], [])
        self.assertEqual(len(gate["verified"]), gate["count"])
        # With no rejections, every binary the walk classified was admitted. The gate also
        # admits files that merely occupy an allowed asset path, so its count is a lower
        # bound on, not an equal of, the classified binary count.
        self.assertGreaterEqual(gate["count"], report["files"]["binary"])
        self.assertEqual(sorted(gate["verified"]), gate["verified"])
        for relative in gate["verified"]:
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_the_report_still_carries_every_pre_existing_field(self) -> None:
        # AC-013: exposing binary paths must not weaken the checks that were already there.
        report = validate_content_integrity()
        self.assertEqual(set(report), {"verified", "external", "files", "binary_assets"})
        self.assertEqual(set(report["files"]), {"text", "binary"})
        self.assertGreater(report["files"]["text"], 0)
        self.assertTrue(all(" -> " in item for item in report["verified"]))
        self.assertIn("policy_version", report["binary_assets"])

    def test_the_hardcoded_zero_binary_assertion_is_gone(self) -> None:
        # The needles are assembled at runtime so this check does not match itself.
        source = (ROOT / "tests/test_integrity.py").read_text(encoding="utf-8")
        binary_count = '["files"]' + '["binary"]'
        self.assertNotIn(binary_count + ", 0", source)
        self.assertNotIn(binary_count + " == 0", source)
        self.assertIn(binary_count, source)

    def test_every_repo_reference_resolves_to_an_existing_file(self) -> None:
        for source, uri, expected in hashed_content_references():
            self.assertTrue(expected.startswith(HASH_PREFIX), f"{source}: {uri}")
            if uri.startswith("repo://"):
                self.assertTrue((ROOT / uri.removeprefix("repo://")).is_file(), f"{source}: {uri}")

    def test_repository_files_skip_scratch_worktrees_and_caches(self) -> None:
        found = {path.relative_to(ROOT).as_posix() for path in repository_files()}
        self.assertIn("operations/collaboration.yaml", found)
        self.assertFalse([item for item in found if "/worktrees/" in item or "__pycache__" in item])

    def test_the_sys_cld_0011_artifact_verifies_from_a_crlf_checkout(self) -> None:
        # The exact regression: rewrite the protocol file with Windows endings and the stored
        # Artifact Contract hash must still verify.
        artifact = load_json("artifacts/SYS-CLD-0011-artifact.json")
        relative = artifact["uri"].removeprefix("repo://")
        body = (ROOT / relative).read_bytes().replace(b"\r\n", b"\n")
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            lf_path = base / "lf.yaml"
            crlf_path = base / "crlf.yaml"
            lf_path.write_bytes(body)
            crlf_path.write_bytes(body.replace(b"\n", b"\r\n"))
            self.assertTrue(verify_file(lf_path, artifact["content_hash"], label=relative).matches)
            self.assertTrue(verify_file(crlf_path, artifact["content_hash"], label=relative).matches)
            tampered = base / "tampered.yaml"
            tampered.write_bytes(body + b"guards:\n  commit_without_user_approval: allowed\n")
            self.assertFalse(verify_file(tampered, artifact["content_hash"], label=relative).matches)


class ArtifactHashDriftTests(unittest.TestCase):
    """The R2 artifact's declared component hashes must track the files they name."""

    def test_declared_component_hashes_match_their_files(self) -> None:
        specification = load_json("artifacts/R2-RNG-0001-artifact.json")["specification"]
        self.assertEqual(specification["statistics_module_hash"], hash_file(ROOT / specification["statistics_module"]))
        self.assertEqual(specification["record_schema_hash"], hash_file(ROOT / specification["record_schema"]))

    def test_a_stale_component_hash_fails_the_r2_step(self) -> None:
        from scripts.validate_baseline import R2_RNG_INPUT_FILES, validate_r2_rng

        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            for relative in R2_RNG_INPUT_FILES:
                destination = base / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, destination)
            path = base / "artifacts/R2-RNG-0001-artifact.json"
            artifact = json.loads(path.read_text(encoding="utf-8"))
            artifact["specification"]["statistics_module_hash"] = HASH_PREFIX + "0" * 64
            path.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(BaselineValidationError, "statistics_module_hash"):
                validate_r2_rng(root=base)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
