"""SYS-IMG-0013 gate tests for the ``codex_imagegen`` art-only managed image provider.

The registration moved exactly one boundary: the ``image`` route. Everything else -- the
Claude-only programming boundary of ADR-0003, the disabled Codex code provider, and the
unconfigured ``layer_ai`` entry -- had to stay where it was. ``image_provider_problems``
is the executable form of that boundary; the positive test asserts the repository is clean
under it and the negative tests mutate a copy of the repository state to prove each rule
actually rejects rather than passing vacuously.

The gate lives here rather than in ``scripts/validate_baseline.py`` because SYS-IMG-0013
declares ``tests/test_image_provider.py`` as its gate deliverable and does not list the
validator among its deliverables or its rollback surface.
"""

from __future__ import annotations

import copy
import json
import unittest

from studio_core.collaboration import evaluate_provider_activation, scan_for_plaintext_secrets
from studio_core.provider import select_provider
from studio_core.rng import compute_event_hash
from scripts.validate_baseline import (
    ROOT,
    BaselineValidationError,
    load_json,
    load_yaml,
    validate_instance,
)

PROVIDER_ID = "codex_imagegen"
PROOF_PATH = "providers/evidence/SYS-IMG-0013-codex-imagegen-connection-proof.yaml"
GUIDE_PATH = "docs/providers/SYS-IMG-0013-codex-imagegen-art-provider.md"
EVENTS_PATH = "audit/events/SYS-IMG-0013-events.json"

#: Capabilities ADR-0003 keeps away from every Codex-backed entry.
FORBIDDEN_CAPABILITIES = ("code", "reasoning", "evaluation", "orchestration")

#: Routes the image registration was not allowed to touch.
CLAUDE_ROUTES = ("code", "reasoning", "evaluation")

#: Fingerprints of the two pre-registration probe images. They are connectivity evidence and
#: candidate assets only; neither may ever appear as an Artifact Contract ``content_hash``.
PROBE_FINGERPRINTS = (
    "b130c05b29a29513dfefb3648c1935fa68f86822c17679c515b64ce45d5ad689",
    "920861ca200bb0ed8b273bb78a8acfd235e42cf392ac3c24eadcebc32bad0e62",
)

#: Values that record an unavailable managed model instead of inventing one.
UNAVAILABLE_MODEL_VALUES = (None, "unavailable", "UNAVAILABLE")


def routed_provider_ids(routing: dict) -> set[str]:
    return {
        provider_id
        for route in routing["routes"].values()
        for provider_id in [route["preferred"], *route.get("fallbacks", [])]
    }


def proof_is_complete(proof: dict | None) -> bool:
    """Return whether a connection proof authorises promotion to ``ENABLED``.

    A proof only counts when it targets this provider, every *blocking* probe passed, and the
    recorder signed off separately from the verifier. A non-blocking probe may report anything
    without unblocking activation on its own.
    """

    if not isinstance(proof, dict) or proof.get("provider_id") != PROVIDER_ID:
        return False
    if proof.get("user_authorization", {}).get("granted") is not True:
        return False
    if proof.get("recorded_by") == proof.get("verified_by"):
        return False
    blocking = [probe for probe in proof.get("probes", []) if probe.get("blocking")]
    if not blocking or any(probe.get("result") != "PASS" for probe in blocking):
        return False
    return proof.get("overall_result") == "PASS" and proof.get("activation_recommendation") == "ENABLE"


def image_provider_problems(registry: dict, routing: dict, proof: dict | None) -> list[str]:
    """Return every SYS-IMG-0013 boundary violation in the supplied provider state."""

    problems: list[str] = []
    providers = {item["provider_id"]: item for item in registry["providers"]}
    ids = [item["provider_id"] for item in registry["providers"]]
    if len(ids) != len(set(ids)):
        problems.append("provider registry contains duplicate provider_id values")

    entry = providers.get(PROVIDER_ID)
    if entry is None:
        problems.append(f"{PROVIDER_ID} is not registered")
        return problems

    if entry["capabilities"] != ["image"]:
        problems.append(f"{PROVIDER_ID}: capabilities must be exactly ['image'], found {entry['capabilities']!r}")
    granted = set(entry["capabilities"]) & set(FORBIDDEN_CAPABILITIES)
    if granted:
        problems.append(f"{PROVIDER_ID}: forbidden capabilities {sorted(granted)!r}")
    if not str(entry.get("credential_ref", "")).startswith("secret-ref://"):
        problems.append(f"{PROVIDER_ID}: credentials must be recorded as a secret-ref:// reference")

    complete = proof_is_complete(proof)
    image_route = routing["routes"].get("image", {})
    if entry["status"] == "ENABLED" and not complete:
        problems.append(f"{PROVIDER_ID}: ENABLED without a complete connection proof")
    if not complete:
        if entry["status"] != "DISABLED_UNTIL_CONFIGURED":
            problems.append(f"{PROVIDER_ID}: must stay DISABLED_UNTIL_CONFIGURED without proof")
        if image_route.get("preferred") == PROVIDER_ID:
            problems.append("image route switched to an unproven provider")
    if image_route.get("fallbacks") != []:
        problems.append("the image route must not declare a model fallback")

    layer_ai = providers.get("layer_ai", {})
    if layer_ai.get("status") != "DISABLED_UNTIL_CONFIGURED":
        problems.append(f"layer_ai must stay DISABLED_UNTIL_CONFIGURED, found {layer_ai.get('status')!r}")
    routed = routed_provider_ids(routing)
    if "layer_ai" in routed:
        problems.append("layer_ai must not appear in any route until a separate task configures it")

    codex = providers.get("codex_primary", {})
    if codex.get("status") != "DISABLED":
        problems.append(f"codex_primary must stay DISABLED, found {codex.get('status')!r}")
    if codex.get("disabled_reason") != "user_selected_claude_only_programming":
        problems.append("codex_primary must keep its ADR-0003 disabled_reason")
    if "codex_primary" in routed:
        problems.append("codex_primary must not appear in any route")

    for capability in CLAUDE_ROUTES:
        route = routing["routes"].get(capability, {})
        if route.get("preferred") != "claude_agent" or route.get("fallbacks") != []:
            problems.append(f"{capability} route must remain claude_agent with no fallback")

    return problems


class ImageProviderRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_yaml("providers/registry.yaml")
        self.routing = load_yaml("providers/routing-policy.yaml")
        self.proof = load_yaml(PROOF_PATH)
        self.entry = next(
            item for item in self.registry["providers"] if item["provider_id"] == PROVIDER_ID
        )

    # -- positive state ----------------------------------------------------------------

    def test_repository_state_satisfies_the_image_provider_gate(self) -> None:
        self.assertEqual(image_provider_problems(self.registry, self.routing, self.proof), [])

    def test_provider_is_registered_with_the_image_capability_only(self) -> None:
        self.assertEqual(self.entry["capabilities"], ["image"])
        self.assertEqual(self.entry["status"], "ENABLED")
        self.assertEqual(self.entry["activation_evidence"], PROOF_PATH)
        self.assertEqual(self.entry["activated_by_task"], "SYS-IMG-0013")
        for capability in FORBIDDEN_CAPABILITIES:
            self.assertNotIn(capability, self.entry["capabilities"])

    def test_image_route_selects_the_managed_provider(self) -> None:
        request = copy.deepcopy(load_json("providers/examples/request.example.json"))
        request["capability"] = "image"
        decision = select_provider(request, self.registry, self.routing)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, "ROUTED")
        self.assertEqual(decision.provider_id, PROVIDER_ID)
        self.assertEqual(self.routing["routes"]["image"], {"preferred": PROVIDER_ID, "fallbacks": []})

    def test_connection_proof_is_schema_valid_and_fully_passing(self) -> None:
        validate_instance(self.proof, load_json("providers/connection-proof.schema.json"))
        self.assertTrue(proof_is_complete(self.proof))
        self.assertNotEqual(self.proof["recorded_by"], self.proof["verified_by"])
        self.assertEqual(self.proof["task_id"], "SYS-IMG-0013")

    def test_credentials_are_references_and_no_secret_values_are_recorded(self) -> None:
        self.assertTrue(self.entry["credential_ref"].startswith("secret-ref://"))
        self.assertEqual(self.proof["credential_ref"], self.entry["credential_ref"])
        self.assertFalse(self.proof["secret_values_recorded"])
        self.assertFalse(self.proof["environment"]["contains_secret_values"])
        self.assertEqual(scan_for_plaintext_secrets(self.proof), [])
        self.assertEqual(scan_for_plaintext_secrets(self.entry), [])

    def test_unavailable_managed_model_is_recorded_rather_than_invented(self) -> None:
        self.assertIn(self.proof["environment"]["model"], UNAVAILABLE_MODEL_VALUES)

    def test_probe_outputs_are_not_promoted_to_artifact_contracts(self) -> None:
        declared = set()
        for path in sorted((ROOT / "artifacts").glob("*.json")):
            artifact = load_json(f"artifacts/{path.name}")
            declared.add(artifact["content_hash"])
            declared.add(artifact["source"]["input_hash"])
        for fingerprint in PROBE_FINGERPRINTS:
            self.assertNotIn(f"sha256:{fingerprint}", declared)
            self.assertIn(fingerprint, (ROOT / GUIDE_PATH).read_text(encoding="utf-8"))

    def test_layer_ai_stays_unconfigured_with_no_invented_threshold(self) -> None:
        layer_ai = next(item for item in self.registry["providers"] if item["provider_id"] == "layer_ai")
        self.assertEqual(layer_ai["status"], "DISABLED_UNTIL_CONFIGURED")
        self.assertNotIn("layer_ai", routed_provider_ids(self.routing))
        guide = (ROOT / GUIDE_PATH).read_text(encoding="utf-8")
        for marker in (
            "layer_ai_usage_threshold: UNSET",
            "layer_ai_switch_criteria: UNSET",
            "layer_ai_switch_date: UNSET",
        ):
            self.assertIn(marker, guide)

    def test_claude_programming_boundary_is_unchanged(self) -> None:
        codex = next(item for item in self.registry["providers"] if item["provider_id"] == "codex_primary")
        self.assertEqual(codex["status"], "DISABLED")
        self.assertEqual(codex["disabled_reason"], "user_selected_claude_only_programming")
        routed = routed_provider_ids(self.routing)
        self.assertNotIn("codex_primary", routed)
        for capability in CLAUDE_ROUTES:
            self.assertEqual(self.routing["routes"][capability], {"preferred": "claude_agent", "fallbacks": []})

    def test_image_proof_cannot_activate_the_codex_code_provider(self) -> None:
        # The SYS-CLD-0011 activation gate is scoped to claude_agent; this image evidence must
        # not be usable to promote any other provider through it.
        for provider_id in (PROVIDER_ID, "codex_primary"):
            decision = evaluate_provider_activation(provider_id, "ENABLED", self.proof)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.code, "PROVIDER_DENIED")
            self.assertEqual(decision.resulting_status, "DISABLED_UNTIL_CONFIGURED")

    def test_audit_events_are_schema_valid_secret_free_and_chained(self) -> None:
        schema = load_json("audit/audit-event.schema.json")
        document = load_json(EVENTS_PATH)
        previous = None
        self.assertTrue(document["events"])
        for index, event in enumerate(document["events"]):
            validate_instance(event, schema)
            self.assertEqual(event["task_id"], "SYS-IMG-0013")
            self.assertFalse(event["contains_secret"])
            self.assertEqual(event.get("previous_event_hash"), previous, f"event {index} is not chained")
            self.assertEqual(event["event_hash"], compute_event_hash(event), f"event {index} hash mismatch")
            previous = event["event_hash"]
        self.assertEqual(scan_for_plaintext_secrets(document), [])

    # -- negative state ----------------------------------------------------------------

    def test_forbidden_capability_is_rejected(self) -> None:
        for capability in FORBIDDEN_CAPABILITIES:
            registry = copy.deepcopy(self.registry)
            entry = next(item for item in registry["providers"] if item["provider_id"] == PROVIDER_ID)
            entry["capabilities"] = ["image", capability]
            problems = image_provider_problems(registry, self.routing, self.proof)
            self.assertTrue(any(capability in problem for problem in problems))

    def test_enabling_without_evidence_is_rejected(self) -> None:
        problems = image_provider_problems(self.registry, self.routing, None)
        self.assertTrue(any("without a complete connection proof" in problem for problem in problems))

    def test_incomplete_evidence_blocks_the_route_switch(self) -> None:
        proof = copy.deepcopy(self.proof)
        proof["probes"][0]["result"] = "FAIL"
        proof["overall_result"] = "INCOMPLETE"
        problems = image_provider_problems(self.registry, self.routing, proof)
        self.assertTrue(any("unproven provider" in problem for problem in problems))
        self.assertTrue(any("DISABLED_UNTIL_CONFIGURED" in problem for problem in problems))

    def test_layer_ai_fallback_registration_is_rejected(self) -> None:
        routing = copy.deepcopy(self.routing)
        routing["routes"]["image"]["fallbacks"] = ["layer_ai"]
        problems = image_provider_problems(self.registry, routing, self.proof)
        self.assertTrue(any("layer_ai must not appear" in problem for problem in problems))
        self.assertTrue(any("model fallback" in problem for problem in problems))

    def test_enabling_layer_ai_without_its_own_task_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        layer_ai = next(item for item in registry["providers"] if item["provider_id"] == "layer_ai")
        layer_ai["status"] = "ENABLED"
        problems = image_provider_problems(registry, self.routing, self.proof)
        self.assertTrue(any("layer_ai must stay DISABLED_UNTIL_CONFIGURED" in problem for problem in problems))

    def test_codex_code_provider_promotion_is_rejected(self) -> None:
        registry = copy.deepcopy(self.registry)
        codex = next(item for item in registry["providers"] if item["provider_id"] == "codex_primary")
        codex["status"] = "ENABLED"
        problems = image_provider_problems(registry, self.routing, self.proof)
        self.assertTrue(any("codex_primary must stay DISABLED" in problem for problem in problems))

    def test_code_route_substitution_is_rejected(self) -> None:
        routing = copy.deepcopy(self.routing)
        routing["routes"]["code"] = {"preferred": "claude_agent", "fallbacks": ["codex_primary"]}
        problems = image_provider_problems(self.registry, routing, self.proof)
        self.assertTrue(any("code route must remain claude_agent" in problem for problem in problems))
        self.assertTrue(any("codex_primary must not appear" in problem for problem in problems))

    def test_plaintext_credential_in_evidence_is_detected(self) -> None:
        tampered = copy.deepcopy(self.proof)
        tampered["credential_ref"] = "api_key=" + "A" * 24
        self.assertTrue(scan_for_plaintext_secrets(tampered))

    def test_tampered_audit_event_breaks_the_chain(self) -> None:
        document = copy.deepcopy(load_json(EVENTS_PATH))
        document["events"][0]["action"] = "TAMPERED"
        self.assertNotEqual(document["events"][0]["event_hash"], compute_event_hash(document["events"][0]))

    def test_task_contract_input_hashes_match_the_current_files(self) -> None:
        from studio_core.integrity import verify_file

        task = load_json("tasks/SYS-IMG-0013.json")
        tracked = {
            item["uri"].removeprefix("repo://"): item["content_hash"]
            for item in task["inputs"]
            if item["uri"].startswith("repo://")
        }
        for relative in ("providers/registry.yaml", "providers/routing-policy.yaml"):
            decision = verify_file(ROOT / relative, tracked[relative], label=relative)
            self.assertTrue(decision.matches, decision.message)

    def test_task_contract_is_schema_valid_and_delegatable(self) -> None:
        task = load_json("tasks/SYS-IMG-0013.json")
        validate_instance(task, load_json("contracts/task.schema.json"))
        self.assertEqual(task["owner_agent_id"], "A-02")
        self.assertIn(task["status"], {"READY", "IN_PROGRESS"})
        self.assertTrue(task["budget"]["stop_on_limit"])
        self.assertEqual(task["security"]["secrets_policy"], "REFERENCE_ONLY")
        with self.assertRaises(BaselineValidationError):
            invalid = copy.deepcopy(task)
            invalid["inputs"] = []
            validate_instance(invalid, load_json("contracts/task.schema.json"))


if __name__ == "__main__":  # pragma: no cover - convenience entry point
    unittest.main()
