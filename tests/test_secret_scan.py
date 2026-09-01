"""Tests for the deterministic repository secret scan and the SYS-CI-0012 CI workflow.

Positive samples are assembled from fragments at runtime so that this file never contains a
literal credential-shaped string. That keeps the suite honest: the repository scan covers
tests/ as well, and a literal sample here would either fail the scan or force a blanket
exemption over the file that also hid real mistakes.
"""

from __future__ import annotations

import dataclasses
import re
import unittest
from pathlib import Path

import yaml

from scripts.scan_secrets import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, run
from studio_core.secret_scan import (
    ALLOW_MARKER,
    DEFAULT_CONFIG,
    ROOT,
    RULES,
    ScanConfig,
    format_report,
    iter_scannable_files,
    scan_repository,
    scan_text,
)

WORKFLOW_PATH = ROOT / ".github/workflows/ci.yml"
FIXTURE_PATH = ROOT / "tests/fixtures/secret_scan/allowlisted-sample.txt"

#: One credential-shaped sample per rule, built by concatenation. See the module docstring.
POSITIVE_SAMPLES: dict[str, str] = {
    "anthropic-api-key": "sk-" + "ant-" + "A" * 24,
    "openai-style-api-key": "sk-" + "B" * 32,
    "github-token": "ghp" + "_" + "c" * 36,
    "github-fine-grained-token": "github" + "_pat_" + "d" * 30,
    "slack-token": "xox" + "b-" + "1234567890-abcdef",
    "aws-access-key-id": "AKIA" + "IOSFODNN7EXAMPLE",
    "google-api-key": "AIza" + "e" * 35,
    "private-key-block": "-----BEGIN " + "RSA PRIVATE KEY" + "-----",
    "bearer-token": "Authorization: Bearer " + "f" * 32,
    "assigned-credential": "api_key" + " = " + "g" * 24,
    "json-web-token": "eyJ" + "h" * 16 + "." + "i" * 16 + "." + "j" * 16,
}


#: The only action references the workflow may make, as ``action -> (commit sha, release tag)``.
#:
#: An "official" owner is not a supply-chain control: ``actions/checkout@v4`` resolves through a
#: mutable tag, so upstream can point it at different code without the workflow changing. Only a
#: full 40-character commit SHA is immutable. The release tag is carried as a trailing comment so
#: a reviewer can still tell which version is pinned; both halves are asserted below, which makes
#: this mapping the single place a version bump has to be approved.
APPROVED_ACTION_PINS: dict[str, tuple[str, str]] = {
    "actions/checkout": ("11d5960a326750d5838078e36cf38b85af677262", "v4"),
    "actions/setup-python": ("a26af69be951a213d495a4c3e4e4022e16d87065", "v5"),
}

#: Any ``uses:`` line at all, so an unpinned one cannot escape by not matching the strict form.
_ANY_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<reference>\S.*?)\s*$")

#: The one accepted shape: ``uses: owner/repo@<40 hex> # <tag>``.
_PINNED_USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)"
    r"@(?P<sha>[0-9a-f]{40})\s+#\s*(?P<tag>\S+)\s*$"
)


def _uses_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if _ANY_USES.match(line)]


def _write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def _workflow() -> dict:
    document = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _triggers(workflow: dict) -> dict:
    # PyYAML resolves the unquoted GitHub Actions key ``on`` to the boolean True (YAML 1.1).
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


class SecretRuleTests(unittest.TestCase):
    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.rule_id for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_a_positive_sample(self) -> None:
        self.assertEqual(set(POSITIVE_SAMPLES), {rule.rule_id for rule in RULES})

    def test_every_rule_detects_its_positive_sample(self) -> None:
        for rule_id, sample in POSITIVE_SAMPLES.items():
            with self.subTest(rule_id=rule_id):
                found = {finding.rule_id for finding in scan_text(sample, path="sample.txt")}
                self.assertIn(rule_id, found)

    def test_findings_are_reported_in_deterministic_order(self) -> None:
        text = "\n".join(
            [
                "clean line",
                POSITIVE_SAMPLES["aws-access-key-id"],
                "another clean line",
                POSITIVE_SAMPLES["github-token"] + " " + POSITIVE_SAMPLES["google-api-key"],
            ]
        )
        first = scan_text(text, path="sample.txt")
        second = scan_text(text, path="sample.txt")
        self.assertEqual(first, second)
        self.assertEqual(
            [(finding.line, finding.column) for finding in first],
            sorted((finding.line, finding.column) for finding in first),
        )

    def test_excerpt_never_contains_the_matched_secret(self) -> None:
        for rule_id, sample in POSITIVE_SAMPLES.items():
            with self.subTest(rule_id=rule_id):
                line = f"config: {sample}"
                findings = scan_text(line, path="sample.txt")
                self.assertTrue(findings)
                for finding in findings:
                    self.assertNotIn(sample, finding.excerpt)
                    self.assertIn("<redacted:", finding.excerpt)

    def test_report_rendering_never_echoes_the_secret(self) -> None:
        with self.subTest("format_report"):
            sample = POSITIVE_SAMPLES["anthropic-api-key"]
            import tempfile

            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _write(root, "leak.env", f"anthropic: {sample}\n")
                rendered = format_report(scan_repository(root), verbose=True)
                self.assertNotIn(sample, rendered)
                self.assertIn("anthropic-api-key", rendered)

    def test_policy_vocabulary_is_not_flagged(self) -> None:
        text = "\n".join(
            [
                "credential_ref: secret-ref://claude/agent-auth",
                "secrets_policy: REFERENCE_ONLY",
                "secret_storage: os_credential_manager",
                "content_hash: sha256:" + "0" * 64,
                "documentation: https://json-schema.org/draft/2020-12/schema",
                "note: password rotation is handled by the broker, never by this repository",
                "uri: repo://providers/evidence/claude-connection-proof.yaml",
            ]
        )
        self.assertEqual(scan_text(text, path="policy.yaml"), [])


class AllowlistTests(unittest.TestCase):
    def test_inline_marker_exempts_its_own_line(self) -> None:
        line = f"{POSITIVE_SAMPLES['aws-access-key-id']}  # {ALLOW_MARKER} -- sample"
        self.assertEqual(scan_text(line, path="fixture.txt"), [])

    def test_marker_on_the_preceding_line_exempts_the_next_line(self) -> None:
        text = f"# {ALLOW_MARKER} -- sample\n{POSITIVE_SAMPLES['github-token']}\n"
        self.assertEqual(scan_text(text, path="fixture.txt"), [])

    def test_marker_does_not_exempt_two_lines_down(self) -> None:
        text = f"# {ALLOW_MARKER}\nclean\n{POSITIVE_SAMPLES['github-token']}\n"
        findings = scan_text(text, path="fixture.txt")
        self.assertEqual([finding.line for finding in findings], [3])

    def test_removing_the_marker_restores_detection(self) -> None:
        sample = POSITIVE_SAMPLES["aws-access-key-id"]
        marked = f"{sample}  # {ALLOW_MARKER}"
        self.assertEqual(scan_text(marked, path="fixture.txt"), [])
        self.assertTrue(scan_text(sample, path="fixture.txt"))

    def test_path_allowlist_skips_the_whole_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(root, "config/leak.env", POSITIVE_SAMPLES["openai-style-api-key"] + "\n")

            self.assertFalse(scan_repository(root).ok)

            allowlisted = DEFAULT_CONFIG.with_allowlist(["config/leak.env"])
            report = scan_repository(root, allowlisted)
            self.assertTrue(report.ok)
            self.assertIn(
                ("config/leak.env", "ALLOWLISTED_PATH"),
                [(entry.path, entry.reason) for entry in report.skipped],
            )

    def test_with_allowlist_does_not_mutate_the_default_config(self) -> None:
        DEFAULT_CONFIG.with_allowlist(["anything.txt"])
        self.assertEqual(DEFAULT_CONFIG.allowlisted_paths, frozenset())


class ExclusionTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)

    def test_binary_files_are_skipped(self) -> None:
        payload = POSITIVE_SAMPLES["aws-access-key-id"].encode("ascii") + b"\x00\x01\x02"
        _write(self.root, "assets/blob.dat", payload)
        report = scan_repository(self.root)
        self.assertTrue(report.ok)
        self.assertIn(
            ("assets/blob.dat", "BINARY"),
            [(entry.path, entry.reason) for entry in report.skipped],
        )

    def test_undecodable_bytes_are_treated_as_binary(self) -> None:
        _write(self.root, "assets/latin.dat", b"\xff\xfe" + POSITIVE_SAMPLES["github-token"].encode())
        self.assertTrue(scan_repository(self.root).ok)

    def test_ignored_directories_are_pruned(self) -> None:
        sample = POSITIVE_SAMPLES["google-api-key"] + "\n"
        for relative in (
            "__pycache__/cached.txt",
            ".git/config",
            "node_modules/pkg/index.js",
            ".venv/lib/site.py",
            "build/out.txt",
            ".claude/worktrees/scratch/leak.txt",
        ):
            _write(self.root, relative, sample)
        report = scan_repository(self.root)
        self.assertTrue(report.ok, msg=format_report(report))
        self.assertEqual(report.scanned_files, 0)

    def test_generated_and_binary_suffixes_are_skipped(self) -> None:
        sample = POSITIVE_SAMPLES["slack-token"] + "\n"
        for relative in ("app.pyc", "logo.png", "bundle.min.js", "poetry.lock", "app.js.map"):
            _write(self.root, relative, sample)
        report = scan_repository(self.root)
        self.assertTrue(report.ok, msg=format_report(report))
        self.assertEqual(report.scanned_files, 0)

    def test_oversized_files_are_skipped_and_reported(self) -> None:
        _write(self.root, "big.txt", POSITIVE_SAMPLES["github-token"] + "\n")
        config = dataclasses.replace(DEFAULT_CONFIG, max_file_bytes=8)
        report = scan_repository(self.root, config)
        self.assertTrue(report.ok)
        self.assertIn(("big.txt", "TOO_LARGE"), [(e.path, e.reason) for e in report.skipped])

    def test_file_walk_is_sorted_and_repeatable(self) -> None:
        for relative in ("zeta.txt", "alpha.txt", "nested/mid.txt"):
            _write(self.root, relative, "clean\n")
        first = [path.relative_to(self.root).as_posix() for path in iter_scannable_files(self.root)]
        self.assertEqual(first, sorted(first))
        self.assertEqual(
            first,
            [path.relative_to(self.root).as_posix() for path in iter_scannable_files(self.root)],
        )

    def test_repeated_scans_produce_identical_reports(self) -> None:
        _write(self.root, "a.txt", POSITIVE_SAMPLES["json-web-token"] + "\n")
        _write(self.root, "b.txt", POSITIVE_SAMPLES["bearer-token"] + "\n")
        self.assertEqual(scan_repository(self.root), scan_repository(self.root))


class ScanConfigTests(unittest.TestCase):
    def test_default_config_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            DEFAULT_CONFIG.max_file_bytes = 1  # type: ignore[misc]

    def test_worktree_prefix_is_excluded_by_default(self) -> None:
        self.assertIn(".claude/worktrees/", DEFAULT_CONFIG.ignored_path_prefixes)

    def test_config_is_a_scan_config(self) -> None:
        self.assertIsInstance(DEFAULT_CONFIG, ScanConfig)


class RepositoryScanTests(unittest.TestCase):
    def test_repository_working_tree_is_clean(self) -> None:
        report = scan_repository(ROOT)
        self.assertTrue(report.ok, msg=format_report(report))
        self.assertGreater(report.scanned_files, 0)

    def test_committed_fixture_exists_and_is_exempt_only_by_marker(self) -> None:
        text = FIXTURE_PATH.read_text(encoding="utf-8")
        self.assertEqual(scan_text(text, path="fixture.txt"), [])
        stripped = "\n".join(line.split("#")[0].rstrip() for line in text.splitlines())
        self.assertTrue(
            scan_text(stripped, path="fixture.txt"),
            msg="the fixture must still be detectable once its allow markers are removed",
        )

    def test_fixture_false_positive_control_lines_are_never_flagged(self) -> None:
        control = [
            line
            for line in FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and ALLOW_MARKER not in line
        ]
        self.assertTrue(control)
        self.assertEqual(scan_text("\n".join(control), path="fixture.txt"), [])


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name)

    def test_clean_tree_exits_zero(self) -> None:
        _write(self.root, "readme.md", "nothing to see here\n")
        code, rendered = run(["--root", str(self.root)])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("[PASS]", rendered)

    def test_findings_exit_nonzero_without_echoing_the_secret(self) -> None:
        sample = POSITIVE_SAMPLES["anthropic-api-key"]
        _write(self.root, "leak.env", f"anthropic: {sample}\n")
        code, rendered = run(["--root", str(self.root)])
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertNotEqual(code, EXIT_OK)
        self.assertIn("[FAIL]", rendered)
        self.assertNotIn(sample, rendered)

    def test_allow_path_option_suppresses_a_known_fixture(self) -> None:
        _write(self.root, "fixtures/leak.env", POSITIVE_SAMPLES["github-token"] + "\n")
        self.assertEqual(run(["--root", str(self.root)])[0], EXIT_FINDINGS)
        code, _ = run(["--root", str(self.root), "--allow-path", "fixtures/leak.env"])
        self.assertEqual(code, EXIT_OK)

    def test_missing_root_exits_with_the_error_code(self) -> None:
        code, rendered = run(["--root", str(self.root / "does-not-exist")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("[ERROR]", rendered)

    def test_verbose_lists_skipped_files(self) -> None:
        _write(self.root, "blob.dat", b"\x00\x01binary")
        _, rendered = run(["--root", str(self.root), "--verbose"])
        self.assertIn("[SKIP] blob.dat (BINARY)", rendered)

    def test_repository_default_root_passes(self) -> None:
        code, rendered = run([])
        self.assertEqual(code, EXIT_OK, msg=rendered)


class CiWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.workflow = _workflow()
        self.jobs = self.workflow["jobs"]

    def test_workflow_file_exists(self) -> None:
        self.assertTrue(WORKFLOW_PATH.is_file())

    def test_runs_on_pull_requests_and_pushes_to_main(self) -> None:
        triggers = _triggers(self.workflow)
        self.assertEqual(set(triggers), {"push", "pull_request"})
        self.assertEqual(triggers["push"]["branches"], ["main"])

    def test_top_level_permissions_are_read_only(self) -> None:
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})

    def test_every_job_declares_read_only_permissions_and_a_timeout(self) -> None:
        for name, job in self.jobs.items():
            with self.subTest(job=name):
                self.assertEqual(job["permissions"], {"contents": "read"})
                self.assertIsInstance(job["timeout-minutes"], int)
                self.assertLessEqual(job["timeout-minutes"], 30)

    def test_concurrency_cancels_superseded_runs(self) -> None:
        concurrency = self.workflow["concurrency"]
        self.assertTrue(concurrency["cancel-in-progress"])
        self.assertIn("github.ref", concurrency["group"])

    def test_checkout_does_not_persist_credentials(self) -> None:
        checkouts = [
            step
            for job in self.jobs.values()
            for step in job["steps"]
            if str(step.get("uses", "")).startswith("actions/checkout@")
        ]
        self.assertEqual(len(checkouts), len(self.jobs))
        for step in checkouts:
            self.assertIs(step["with"]["persist-credentials"], False)

    def test_every_action_reference_is_pinned_to_its_approved_commit_sha(self) -> None:
        pinned = [_PINNED_USES.match(line) for line in _uses_lines(self.text)]
        self.assertTrue(pinned, msg="the workflow declares no action references")
        for line, match in zip(_uses_lines(self.text), pinned):
            with self.subTest(line=line.strip()):
                self.assertIsNotNone(
                    match,
                    msg="each `uses:` must read `owner/repo@<40-hex sha> # <tag>`",
                )
                assert match is not None  # narrowed for type checkers
                action = match.group("action")
                self.assertIn(action, APPROVED_ACTION_PINS, msg=f"unapproved action: {action}")
                expected_sha, expected_tag = APPROVED_ACTION_PINS[action]
                self.assertEqual(match.group("sha"), expected_sha)
                self.assertEqual(match.group("tag"), expected_tag)

    def test_no_action_is_referenced_by_a_movable_tag_or_branch(self) -> None:
        for line in _uses_lines(self.text):
            reference = _ANY_USES.match(line).group("reference")  # type: ignore[union-attr]
            with self.subTest(reference=reference):
                self.assertRegex(
                    reference,
                    r"^[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$",
                    msg="a tag or branch reference lets upstream change the code CI runs",
                )

    def test_parsed_steps_use_exactly_the_approved_action_pins(self) -> None:
        # The raw-text assertions above cannot see a `uses:` that YAML folds differently, so the
        # parsed document has to agree with the same approved mapping.
        used = [
            str(step["uses"])
            for job in self.jobs.values()
            for step in job["steps"]
            if "uses" in step
        ]
        self.assertEqual(len(used), len(_uses_lines(self.text)))
        self.assertEqual(
            set(used),
            {f"{action}@{sha}" for action, (sha, _) in APPROVED_ACTION_PINS.items()},
        )

    def test_every_approved_pin_is_actually_used(self) -> None:
        referenced = {
            str(step["uses"]).split("@", 1)[0]
            for job in self.jobs.values()
            for step in job["steps"]
            if "uses" in step
        }
        self.assertEqual(referenced, set(APPROVED_ACTION_PINS))

    def test_python_matrix_stays_small_and_matches_the_declared_floor(self) -> None:
        versions = self.jobs["baseline"]["strategy"]["matrix"]["python-version"]
        self.assertEqual(versions, ["3.11", "3.12"])
        self.assertLessEqual(len(versions), 2)

    def test_all_required_checks_are_executed(self) -> None:
        commands = " ".join(
            str(step.get("run", "")) for job in self.jobs.values() for step in job["steps"]
        )
        for required in (
            "python scripts/validate_baseline.py",
            "python -m unittest discover -s tests -v",
            "python -m compileall -q studio_core scripts tests",
            "python scripts/scan_secrets.py",
        ):
            with self.subTest(command=required):
                self.assertIn(required, commands)

    def test_workflow_never_touches_credentials(self) -> None:
        # No step may read the Actions ``secrets`` context or the default token.
        self.assertNotIn("secrets.", self.text.replace("scan_secrets.py", ""))
        self.assertNotIn("GITHUB_TOKEN", self.text)
        self.assertEqual(scan_text(self.text, path=".github/workflows/ci.yml"), [])

    def test_workflow_is_independent_of_other_branches_and_workflows(self) -> None:
        self.assertNotIn("workflow_run", self.text)
        self.assertNotIn("workflow_call", self.text)
        for job in self.jobs.values():
            self.assertNotIn("needs", job)


if __name__ == "__main__":
    unittest.main()
