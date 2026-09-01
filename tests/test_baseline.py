from __future__ import annotations

import copy
import unittest

from studio_core.knowledge import evaluate_retrieval
from studio_core.ledger import post_transaction
from studio_core.provider import select_provider
from studio_core.roulette import load_r1_rules, settle_bet, theoretical_return, valid_selection_sets, validate_bet
from studio_core.rounds import evaluate_round_transition
from studio_core.workflow import evaluate_transition
from scripts.validate_baseline import (
    BaselineValidationError,
    EXPECTED_AGENT_IDS,
    load_json,
    load_yaml,
    validate_agent_registry,
    validate_contracts,
    validate_claude_workspace,
    validate_evals,
    validate_instance,
    validate_knowledge,
    validate_operations,
    validate_policies,
    validate_providers,
    validate_required_files,
    validate_r0_approval,
    validate_r1_roulette,
    validate_roulette,
)


class BaselineTests(unittest.TestCase):
    def test_required_files_and_constitution(self) -> None:
        validate_required_files()

    def test_registry_contains_exactly_nine_agents(self) -> None:
        definitions = validate_agent_registry()
        self.assertEqual(set(definitions), EXPECTED_AGENT_IDS)
        self.assertEqual(len(definitions), 9)

    def test_contract_examples_and_cross_references(self) -> None:
        definitions = validate_agent_registry()
        instances = validate_contracts(definitions)
        self.assertEqual(instances["task"]["task_id"], instances["artifact"]["task_id"])
        self.assertIn(instances["artifact"]["artifact_id"], instances["handoff"]["artifact_refs"])

    def test_task_schema_rejects_missing_goal(self) -> None:
        schema = load_json("contracts/task.schema.json")
        invalid = copy.deepcopy(load_json("examples/task.example.json"))
        invalid.pop("goal")
        with self.assertRaises(BaselineValidationError):
            validate_instance(invalid, schema)

    def test_task_schema_rejects_unknown_property(self) -> None:
        schema = load_json("contracts/task.schema.json")
        invalid = copy.deepcopy(load_json("examples/task.example.json"))
        invalid["unapproved_extension"] = True
        with self.assertRaises(BaselineValidationError):
            validate_instance(invalid, schema)

    def test_artifact_schema_rejects_invalid_hash(self) -> None:
        schema = load_json("contracts/artifact.schema.json")
        invalid = copy.deepcopy(load_json("examples/artifact.example.json"))
        invalid["content_hash"] = "sha256:not-a-real-hash"
        with self.assertRaises(BaselineValidationError):
            validate_instance(invalid, schema)

    def test_handoff_requires_acknowledgement(self) -> None:
        schema = load_json("contracts/handoff.schema.json")
        invalid = copy.deepcopy(load_json("examples/handoff.example.json"))
        invalid["acknowledgement_required"] = False
        with self.assertRaises(BaselineValidationError):
            validate_instance(invalid, schema)

    def test_operations_are_complete(self) -> None:
        values = validate_operations(validate_agent_registry())
        self.assertEqual(len(values["rooms"]["rooms"]), 9)
        self.assertEqual(values["permissions"]["mode"], "deny_by_default")

    def test_workflow_accepts_owner_start(self) -> None:
        task = {"status": "READY", "owner_agent_id": "A-10", "risk_class": "HIGH"}
        decision = evaluate_transition(task, "IN_PROGRESS", actor_agent_id="A-10")
        self.assertTrue(decision.allowed)

    def test_workflow_rejects_non_owner_start(self) -> None:
        task = {"status": "READY", "owner_agent_id": "A-10", "risk_class": "HIGH"}
        decision = evaluate_transition(task, "IN_PROGRESS", actor_agent_id="A-20")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "ACTOR_DENIED")

    def test_workflow_rejects_direct_done(self) -> None:
        task = {"status": "IN_PROGRESS", "owner_agent_id": "A-10", "risk_class": "LOW"}
        decision = evaluate_transition(task, "DONE", actor_agent_id="A-10")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "INVALID_TRANSITION")

    def test_workflow_rejects_high_risk_done_without_approvals(self) -> None:
        task = {"status": "QA", "owner_agent_id": "A-10", "risk_class": "HIGH"}
        decision = evaluate_transition(task, "DONE", actor_agent_id="A-50", evidence_refs=["report://qa/1"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "MISSING_APPROVAL")

    def test_workflow_accepts_high_risk_done_with_approvals(self) -> None:
        task = {"status": "QA", "owner_agent_id": "A-10", "risk_class": "HIGH"}
        decision = evaluate_transition(
            task,
            "DONE",
            actor_agent_id="A-50",
            evidence_refs=["report://qa/1"],
            approvals=["A-50", "A-02", "A-00"],
        )
        self.assertTrue(decision.allowed)

    def test_knowledge_contract_and_retrieval(self) -> None:
        definitions = validate_agent_registry()
        item = validate_knowledge(definitions)
        decision = evaluate_retrieval(
            item, agent_id="A-20", requested_scope="casino-core", max_classification="INTERNAL"
        )
        self.assertTrue(decision.allowed)

    def test_unapproved_knowledge_is_denied(self) -> None:
        item = copy.deepcopy(load_json("knowledge/examples/roulette-policy.example.json"))
        item["status"] = "PROPOSED"
        decision = evaluate_retrieval(
            item, agent_id="A-20", requested_scope="casino-core", max_classification="INTERNAL"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "STATUS_DENIED")

    def test_knowledge_clearance_is_enforced(self) -> None:
        item = copy.deepcopy(load_json("knowledge/examples/roulette-policy.example.json"))
        item["security"]["classification"] = "CONFIDENTIAL"
        decision = evaluate_retrieval(
            item, agent_id="A-20", requested_scope="casino-core", max_classification="INTERNAL"
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CLASSIFICATION_DENIED")

    def test_claude_route_blocks_until_connected(self) -> None:
        values = validate_providers(validate_agent_registry())
        decision = select_provider(values["request"], values["registry"], values["routing"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROVIDER_UNAVAILABLE")

    def test_claude_route_activates_after_health_checked_configuration(self) -> None:
        values = validate_providers(validate_agent_registry())
        registry = copy.deepcopy(values["registry"])
        next(item for item in registry["providers"] if item["provider_id"] == "claude_agent")["status"] = "ENABLED"
        decision = select_provider(values["request"], registry, values["routing"])
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.provider_id, "claude_agent")

    def test_claude_workspace_and_subagents_are_valid(self) -> None:
        values = validate_claude_workspace()
        self.assertEqual(set(values["agents"]), {"client-engineer", "game-server-engineer", "backend-platform-engineer", "code-reviewer"})
        self.assertEqual(values["settings"]["permissions"]["disableBypassPermissionsMode"], "disable")

    def test_provider_budget_limit_is_enforced(self) -> None:
        values = validate_providers(validate_agent_registry())
        request = copy.deepcopy(values["request"])
        request["budget"]["estimated_cost_usd"] = 6.0
        decision = select_provider(request, values["registry"], values["routing"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "BUDGET_EXCEEDED")

    def test_restricted_data_is_not_routed_externally(self) -> None:
        values = validate_providers(validate_agent_registry())
        request = copy.deepcopy(values["request"])
        request["data_classification"] = "RESTRICTED"
        decision = select_provider(request, values["registry"], values["routing"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "POLICY_DENIED")

    def test_unconfigured_art_provider_is_not_selected(self) -> None:
        values = validate_providers(validate_agent_registry())
        request = copy.deepcopy(values["request"])
        request["capability"] = "image"
        decision = select_provider(request, values["registry"], values["routing"])
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "PROVIDER_UNAVAILABLE")

    def test_all_nine_eval_sets_are_valid(self) -> None:
        datasets = validate_evals(validate_agent_registry())
        self.assertEqual(len(datasets), 9)
        self.assertTrue(all(len(dataset["cases"]) >= 2 for dataset in datasets.values()))

    def test_roulette_baseline_and_vectors(self) -> None:
        values = validate_roulette()
        self.assertEqual(len(values["rules"]["table"]["pockets"]), 37)
        self.assertEqual(len(values["vectors"]["vectors"]), 12)

    def test_roulette_zero_loses_even_money(self) -> None:
        result = settle_bet({"type": "red", "selections": [], "stake_units": 100}, 0)
        self.assertEqual(result, {"won": False, "net_change_units": -100, "total_return_units": 0})

    def test_roulette_straight_pays_35_to_1(self) -> None:
        result = settle_bet({"type": "straight", "selections": [17], "stake_units": 100}, 17)
        self.assertEqual(result, {"won": True, "net_change_units": 3500, "total_return_units": 3600})

    def test_roulette_rejects_invalid_result(self) -> None:
        with self.assertRaises(ValueError):
            settle_bet({"type": "straight", "selections": [17], "stake_units": 100}, 37)

    def test_security_cost_audit_and_risk_policies(self) -> None:
        values = validate_policies()
        self.assertEqual(values["security"]["mode"], "deny_by_default")
        self.assertTrue(values["audit"]["integrity"]["immutable"])

    def test_provider_request_schema_rejects_plaintext_secret(self) -> None:
        schema = load_json("providers/request.schema.json")
        invalid = copy.deepcopy(load_json("providers/examples/request.example.json"))
        invalid["permissions"]["secret_refs"] = ["sk-plaintext-secret"]
        with self.assertRaises(BaselineValidationError):
            validate_instance(invalid, schema)

    def test_sys_010_r0_approval_is_valid(self) -> None:
        approval = validate_r0_approval(validate_agent_registry())
        self.assertEqual(approval["decision"], "APPROVED")
        self.assertEqual(approval["final_approver"], "USER")
        self.assertEqual(approval["next_gate"], "R1_RULES_AND_ECONOMY_BASELINE")

    def test_r1_roulette_contracts_are_consistent(self) -> None:
        values = validate_r1_roulette()
        self.assertEqual(values["game_brief"]["status"], "CANDIDATE")
        self.assertAlmostEqual(values["economy"]["mathematics"]["house_edge_decimal"], 1 / 37)

    def test_r1_rejects_non_adjacent_split(self) -> None:
        with self.assertRaises(ValueError):
            validate_bet({"type": "split", "selections": [1, 5], "stake_units": 10})

    def test_r1_accepts_zero_split(self) -> None:
        validate_bet({"type": "split", "selections": [0, 2], "stake_units": 10})

    def test_r1_rejects_invalid_corner_geometry(self) -> None:
        with self.assertRaises(ValueError):
            validate_bet({"type": "corner", "selections": [1, 2, 3, 4], "stake_units": 10})

    def test_r1_all_supported_types_have_common_rtp(self) -> None:
        rules = load_r1_rules()
        for bet_type in rules["payouts"]:
            with self.subTest(bet_type=bet_type):
                values = theoretical_return(bet_type, rules)
                self.assertAlmostEqual(values["rtp"], 36 / 37)
                self.assertAlmostEqual(values["house_edge"], 1 / 37)

    def test_r1_canonical_table_geometry_counts(self) -> None:
        self.assertEqual(len(valid_selection_sets("straight")), 37)
        self.assertEqual(len(valid_selection_sets("split")), 60)
        self.assertEqual(len(valid_selection_sets("street")), 12)
        self.assertEqual(len(valid_selection_sets("corner")), 22)
        self.assertEqual(len(valid_selection_sets("six_line")), 11)

    def test_r1_ledger_posts_balanced_integer_entries(self) -> None:
        transaction = load_json("games/roulette/fixtures/ledger-transaction.example.json")
        result = post_transaction(transaction, {"player:demo": 1000, "escrow:RR-DEMO-0001": 0}, [])
        self.assertTrue(result.applied)
        self.assertEqual(result.balances["player:demo"], 900)
        self.assertEqual(result.balances["escrow:RR-DEMO-0001"], 100)

    def test_r1_ledger_duplicate_is_noop(self) -> None:
        transaction = load_json("games/roulette/fixtures/ledger-transaction.example.json")
        balances = {"player:demo": 900, "escrow:RR-DEMO-0001": 100}
        result = post_transaction(transaction, balances, [transaction["idempotency_key"]])
        self.assertFalse(result.applied)
        self.assertEqual(result.balances, balances)

    def test_r1_ledger_rejects_unbalanced_entries(self) -> None:
        transaction = copy.deepcopy(load_json("games/roulette/fixtures/ledger-transaction.example.json"))
        transaction["entries"][1]["amount_units"] = 99
        with self.assertRaises(ValueError):
            post_transaction(transaction, {"player:demo": 1000, "escrow:RR-DEMO-0001": 0}, [])

    def test_r1_player_balance_cannot_be_negative(self) -> None:
        transaction = load_json("games/roulette/fixtures/ledger-transaction.example.json")
        with self.assertRaises(ValueError):
            post_transaction(transaction, {"player:demo": 50, "escrow:RR-DEMO-0001": 0}, [])

    def test_r1_round_state_is_server_authoritative(self) -> None:
        allowed = evaluate_round_transition("OPEN", "LOCKED", actor="GAME_SERVER", evidence=["audit://lock"])
        denied = evaluate_round_transition("OPEN", "LOCKED", actor="CLIENT", evidence=["audit://lock"])
        self.assertTrue(allowed.allowed)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.code, "ACTOR_DENIED")


if __name__ == "__main__":
    unittest.main()
