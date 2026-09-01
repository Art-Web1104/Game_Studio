from __future__ import annotations

import copy
import unittest

from studio_core.collaboration import (
    evaluate_delegation,
    evaluate_final_gate,
    evaluate_independent_verification,
    evaluate_provider_activation,
    evaluate_role_action,
    expected_paths,
    load_protocol,
    missing_evidence_commands,
    required_commands,
    scan_for_plaintext_secrets,
)
from scripts.validate_baseline import (
    BaselineValidationError,
    evaluate_claude_activation,
    load_connection_proof,
    load_json,
    load_yaml,
    validate_agent_registry,
    validate_collaboration,
    validate_instance,
)


TASK_PATH = "tasks/SYS-CLD-0011.json"
PROOF_PATH = "providers/evidence/SYS-CLD-0011-claude-connection-proof.yaml"
PROOF_SCHEMA_PATH = "providers/connection-proof.schema.json"


def _task() -> dict:
    return copy.deepcopy(load_json(TASK_PATH))


def _handoff() -> dict:
    return copy.deepcopy(load_json("handoffs/SYS-CLD-0011-handoff.json"))


def _proof() -> dict:
    return copy.deepcopy(load_yaml(PROOF_PATH))


class CollaborationProtocolTests(unittest.TestCase):
    def test_protocol_and_task_artifacts_are_consistent(self) -> None:
        values = validate_collaboration(validate_agent_registry())
        self.assertIn("SYS-CLD-0011", values["tasks"])
        self.assertEqual(values["protocol"]["status"], "ACTIVE")

    def test_task_contract_is_ready_and_owned_by_a02(self) -> None:
        task = _task()
        self.assertEqual(task["status"], "READY")
        self.assertEqual(task["owner_agent_id"], "A-02")
        self.assertEqual(task["risk_class"], "MEDIUM")
        self.assertEqual(task["budget"]["max_cost_usd"], 15.0)
        self.assertEqual(task["budget"]["max_runtime_seconds"], 7200)
        self.assertEqual(set(task["approvers"]), {"USER", "A-20", "A-50"})

    def test_expected_paths_are_repeatable(self) -> None:
        paths = expected_paths("SYS-CLD-0011")
        self.assertEqual(paths["task_contract"], TASK_PATH)
        self.assertEqual(paths["artifact_contract"], "artifacts/SYS-CLD-0011-artifact.json")
        self.assertEqual(paths["handoff_packet"], "handoffs/SYS-CLD-0011-handoff.json")

    def test_required_commands_are_the_two_standard_commands(self) -> None:
        self.assertEqual(
            required_commands(),
            ["python scripts/validate_baseline.py", "python -m unittest discover -s tests -v"],
        )


class DelegationGateTests(unittest.TestCase):
    def test_ready_contract_is_delegated_to_claude(self) -> None:
        decision = evaluate_delegation(_task(), console="claude_code", actor_agent_id="A-02")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, "DELEGATED")

    def test_draft_contract_is_rejected(self) -> None:
        task = _task()
        task["status"] = "DRAFT"
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "STATUS_DENIED")

    def test_done_contract_is_rejected(self) -> None:
        task = _task()
        task["status"] = "DONE"
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "STATUS_DENIED")

    def test_codex_console_may_not_implement(self) -> None:
        decision = evaluate_delegation(_task(), console="codex", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CONSOLE_DENIED")

    def test_non_implementer_agent_is_rejected(self) -> None:
        decision = evaluate_delegation(_task(), console="claude_code", actor_agent_id="A-50")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "ACTOR_DENIED")

    def test_confidential_data_is_not_delegated(self) -> None:
        task = _task()
        task["security"]["data_classification"] = "CONFIDENTIAL"
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CLASSIFICATION_DENIED")

    def test_personal_data_is_not_delegated(self) -> None:
        task = _task()
        task["security"]["contains_pii"] = True
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PII_DENIED")

    def test_brokered_secret_use_is_not_delegated(self) -> None:
        task = _task()
        task["security"]["secrets_policy"] = "BROKERED_USE"
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "SECRETS_POLICY_DENIED")

    def test_unbounded_budget_is_rejected(self) -> None:
        task = _task()
        task["budget"]["stop_on_limit"] = False
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "BUDGET_POLICY_DENIED")

    def test_missing_user_approver_is_rejected(self) -> None:
        task = _task()
        task["approvers"] = ["A-20", "A-50"]
        decision = evaluate_delegation(task, console="claude_code", actor_agent_id="A-02")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "APPROVER_MISSING")


class SeparationOfDutiesTests(unittest.TestCase):
    def test_handoff_is_independently_verifiable_by_codex(self) -> None:
        decision = evaluate_independent_verification(
            _handoff(), console="codex", verifier_agent_id="A-20"
        )
        self.assertTrue(decision.allowed)

    def test_generator_may_not_verify_its_own_handoff(self) -> None:
        handoff = _handoff()
        decision = evaluate_independent_verification(
            handoff, console="codex", verifier_agent_id=handoff["from_agent_id"]
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "SELF_VERIFICATION_DENIED")

    def test_claude_console_may_not_independently_verify(self) -> None:
        decision = evaluate_independent_verification(
            _handoff(), console="claude_code", verifier_agent_id="A-20"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CONSOLE_DENIED")

    def test_verification_requires_both_command_evidence(self) -> None:
        handoff = _handoff()
        handoff["verification_evidence"] = [
            item
            for item in handoff["verification_evidence"]
            if item["check"] != "python -m unittest discover -s tests -v"
        ]
        decision = evaluate_independent_verification(
            handoff, console="codex", verifier_agent_id="A-20"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "MISSING_EVIDENCE")

    def test_failed_command_evidence_blocks_verification(self) -> None:
        handoff = _handoff()
        handoff["verification_evidence"][0]["result"] = "FAIL"
        self.assertTrue(missing_evidence_commands(handoff, required_commands()))
        decision = evaluate_independent_verification(
            handoff, console="codex", verifier_agent_id="A-20"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "MISSING_EVIDENCE")

    def test_qa_lead_may_issue_the_final_gate(self) -> None:
        decision = evaluate_final_gate(_handoff(), approver="A-50", verification_result="PASS")
        self.assertTrue(decision.allowed)

    def test_generator_may_not_self_approve_the_final_gate(self) -> None:
        handoff = _handoff()
        decision = evaluate_final_gate(
            handoff, approver=handoff["from_agent_id"], verification_result="PASS"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "SELF_APPROVAL_DENIED")

    def test_final_gate_requires_passing_independent_verification(self) -> None:
        decision = evaluate_final_gate(_handoff(), approver="A-50", verification_result="NOT_RUN")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "VERIFICATION_INCOMPLETE")

    def test_only_claude_may_generate_code(self) -> None:
        for role in ("issuer", "independent_verifier"):
            with self.subTest(role=role):
                decision = evaluate_role_action(role, "code_generation")
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "ACTION_DENIED")
        self.assertTrue(evaluate_role_action("implementer", "implement").allowed)

    def test_implementer_may_not_take_verification_or_final_gate(self) -> None:
        for action in ("independent_verification", "final_qa_approval"):
            with self.subTest(action=action):
                decision = evaluate_role_action("implementer", action)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.code, "ACTION_DENIED")

    def test_unknown_role_is_denied(self) -> None:
        decision = evaluate_role_action("codex_autonomous", "implement")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "ROLE_UNKNOWN")


class ProviderActivationTests(unittest.TestCase):
    def test_live_registry_activation_is_backed_by_proof(self) -> None:
        registry = load_yaml("providers/registry.yaml")
        provider = next(item for item in registry["providers"] if item["provider_id"] == "claude_agent")
        self.assertEqual(provider["status"], "ENABLED")
        self.assertTrue(evaluate_claude_activation(provider["status"]).allowed)

    def test_codex_is_never_a_code_provider(self) -> None:
        registry = load_yaml("providers/registry.yaml")
        provider = next(item for item in registry["providers"] if item["provider_id"] == "codex_primary")
        self.assertEqual(provider["status"], "DISABLED")
        decision = evaluate_provider_activation("codex_primary", "ENABLED", _proof())
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROVIDER_DENIED")

    def test_activation_without_proof_is_denied(self) -> None:
        decision = evaluate_provider_activation("claude_agent", "ENABLED", None)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROOF_MISSING")

    def test_activation_is_denied_when_a_probe_did_not_pass(self) -> None:
        proof = _proof()
        proof["probes"][0]["result"] = "NOT_RUN"
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROBE_INCOMPLETE")

    def test_activation_is_denied_without_user_authorization(self) -> None:
        proof = _proof()
        proof["user_authorization"]["granted"] = False
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "AUTHORIZATION_MISSING")

    def test_activation_is_denied_when_credentials_are_embedded(self) -> None:
        proof = _proof()
        proof["credential_ref"] = "inline-credential-material"
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CREDENTIAL_NOT_REFERENCED")

    def test_activation_is_denied_when_secret_values_were_recorded(self) -> None:
        proof = _proof()
        proof["secret_values_recorded"] = True
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "SECRET_LEAK_RISK")

    def test_activation_is_denied_for_an_unapproved_credential_store(self) -> None:
        proof = _proof()
        proof["credential_source"] = "REPOSITORY_FILE"
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CREDENTIAL_SOURCE_DENIED")

    def test_activation_is_denied_when_overall_result_is_not_pass(self) -> None:
        proof = _proof()
        proof["overall_result"] = "INCOMPLETE"
        decision = evaluate_provider_activation("claude_agent", "ENABLED", proof)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROOF_INCOMPLETE")

    def test_staying_disabled_needs_no_proof(self) -> None:
        decision = evaluate_provider_activation("claude_agent", "DISABLED_UNTIL_CONFIGURED", None)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, "NOT_AN_ACTIVATION")

    def test_recorded_proof_separates_recorder_and_verifier(self) -> None:
        proof = load_connection_proof("claude_agent")
        self.assertIsNotNone(proof)
        self.assertNotEqual(proof["recorded_by"], proof["verified_by"])


class ConnectionProofSchemaTests(unittest.TestCase):
    def test_recorded_proof_is_schema_valid(self) -> None:
        validate_instance(_proof(), load_json(PROOF_SCHEMA_PATH))

    def test_schema_rejects_recorded_secret_values(self) -> None:
        proof = _proof()
        proof["secret_values_recorded"] = True
        with self.assertRaises(BaselineValidationError):
            validate_instance(proof, load_json(PROOF_SCHEMA_PATH))

    def test_schema_rejects_a_plaintext_credential_reference(self) -> None:
        proof = _proof()
        proof["credential_ref"] = "sk-" + "a" * 24
        with self.assertRaises(BaselineValidationError):
            validate_instance(proof, load_json(PROOF_SCHEMA_PATH))

    def test_schema_rejects_a_missing_independent_verifier(self) -> None:
        proof = _proof()
        proof.pop("verified_by")
        with self.assertRaises(BaselineValidationError):
            validate_instance(proof, load_json(PROOF_SCHEMA_PATH))

    def test_schema_rejects_unauthorized_transfer(self) -> None:
        proof = _proof()
        proof["user_authorization"]["granted"] = False
        with self.assertRaises(BaselineValidationError):
            validate_instance(proof, load_json(PROOF_SCHEMA_PATH))

    def test_schema_rejects_confidential_data_classification(self) -> None:
        proof = _proof()
        proof["data_classification"] = "CONFIDENTIAL"
        with self.assertRaises(BaselineValidationError):
            validate_instance(proof, load_json(PROOF_SCHEMA_PATH))


class SecretHygieneTests(unittest.TestCase):
    def test_scanner_flags_plaintext_credential_material(self) -> None:
        sample = "anthropic_key: " + "sk-ant-" + "A" * 32
        self.assertTrue(scan_for_plaintext_secrets(sample))

    def test_scanner_flags_private_key_blocks(self) -> None:
        self.assertTrue(scan_for_plaintext_secrets("-----BEGIN RSA PRIVATE KEY-----"))

    def test_scanner_ignores_secret_references_and_policy_vocabulary(self) -> None:
        protocol_text = "credential_ref: secret-ref://providers/claude\nsecrets_policy: REFERENCE_ONLY\n"
        self.assertEqual(scan_for_plaintext_secrets(protocol_text), [])

    def test_protocol_declares_non_repository_credential_storage(self) -> None:
        credentials = load_protocol()["credentials"]
        self.assertEqual(credentials["storage"], "os_credential_manager")
        self.assertEqual(credentials["repository_values"], "prohibited")
        self.assertEqual(credentials["commit_values"], "prohibited")


if __name__ == "__main__":
    unittest.main()
