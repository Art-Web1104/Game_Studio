"""Provider-neutral model routing reference for SYS-006."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderDecision:
    allowed: bool
    code: str
    provider_id: str | None
    message: str


def select_provider(
    request: dict[str, Any],
    registry: dict[str, Any],
    routing_policy: dict[str, Any],
) -> ProviderDecision:
    if request["budget"]["estimated_cost_usd"] > request["budget"]["max_cost_usd"]:
        return ProviderDecision(False, "BUDGET_EXCEEDED", None, "estimated cost exceeds task budget")
    if request["data_classification"] == "RESTRICTED":
        return ProviderDecision(False, "POLICY_DENIED", None, "restricted data cannot be sent to an external provider")

    route = routing_policy["routes"].get(request["capability"])
    if not route:
        return ProviderDecision(False, "NO_ROUTE", None, "no route exists for the requested capability")
    providers = {item["provider_id"]: item for item in registry["providers"]}
    for provider_id in [route["preferred"], *route.get("fallbacks", [])]:
        provider = providers.get(provider_id)
        if not provider or provider["status"] != "ENABLED":
            continue
        if request["capability"] not in provider["capabilities"]:
            continue
        if request["data_classification"] not in provider["allowed_data_classifications"]:
            continue
        return ProviderDecision(True, "ROUTED", provider_id, "provider satisfies capability and policy")
    return ProviderDecision(False, "PROVIDER_UNAVAILABLE", None, "no configured provider satisfies the request")
