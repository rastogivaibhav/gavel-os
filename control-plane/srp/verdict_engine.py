from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional, Set

from .models import Proposal, Verdict, VerdictReason, VerdictType
from .policy import PolicySet, evaluate_policies

logger = logging.getLogger("srp.verdict")


@dataclass(frozen=True)
class VerdictEngineConfig:
    """Static, deterministic configuration for verdict evaluation."""

    allowed_api_refs: Optional[Set[str]] = None
    max_parameters_bytes: int = 16_000
    max_reasons: int = 8
    policy_set: Optional[PolicySet] = None


class VerdictEngine:
    """Deterministic verdict engine for canonical proposals."""

    def __init__(self, config: Optional[VerdictEngineConfig] = None) -> None:
        self._config = config or VerdictEngineConfig()

    def evaluate(self, proposal: Proposal) -> Verdict:
        """Evaluate a proposal and return a deterministic verdict."""
        reasons: list[VerdictReason] = []
        verdict = VerdictType.ALLOW
        policy_ids: list[str] = []

        # Rule 1: environment must be known
        if proposal.environment not in ("dev", "staging", "prod"):
            verdict = VerdictType.BLOCK
            reasons.append(
                VerdictReason(
                    code="ENV_INVALID",
                    message="Unknown environment",
                    details={"environment": proposal.environment},
                )
            )

        # Rule 2: replay_nonce must be sufficiently strong
        if len(proposal.replay_nonce) < 16:
            verdict = VerdictType.BLOCK
            reasons.append(
                VerdictReason(
                    code="REPLAY_NONCE_WEAK",
                    message="Replay nonce too short",
                    details={"length": len(proposal.replay_nonce)},
                )
            )

        # Rule 3: api_ref allowlist (if configured)
        api_ref = proposal.tool_call.api_ref
        allowed_api_refs = self._config.allowed_api_refs
        if allowed_api_refs is not None and api_ref not in allowed_api_refs:
            verdict = VerdictType.BLOCK
            reasons.append(
                VerdictReason(
                    code="API_NOT_ALLOWED",
                    message="API reference not in allowlist",
                    details={"api_ref": api_ref},
                )
            )

        # Rule 4: parameter size limit
        try:
            encoded = json.dumps(proposal.tool_call.parameters, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError):
            verdict = VerdictType.BLOCK
            reasons.append(
                VerdictReason(
                    code="PARAMS_NOT_SERIALISABLE",
                    message="Parameters are not JSON-serialisable",
                    details={},
                )
            )
            encoded = ""

        if encoded and len(encoded.encode("utf-8")) > self._config.max_parameters_bytes:
            verdict = VerdictType.BLOCK
            reasons.append(
                VerdictReason(
                    code="PARAM_TOO_LARGE",
                    message="Parameters exceed maximum allowed size",
                    details={"bytes": len(encoded.encode("utf-8"))},
                )
            )

        # Apply policy set if configured and no hard validation failure yet,
        # or to potentially escalate/deny even when base checks pass.
        if self._config.policy_set is not None:
            result = evaluate_policies(self._config.policy_set, proposal)
            if result.verdict is not None:
                verdict = result.verdict
                policy_ids.extend(result.policy_ids)
                reasons.extend(result.reasons)

        # Truncate reasons deterministically if necessary
        if len(reasons) > self._config.max_reasons:
            reasons = reasons[: self._config.max_reasons]

        # If no blocking reasons and still ALLOW, add a generic OK reason
        if verdict == VerdictType.ALLOW and not reasons:
            reasons.append(
                VerdictReason(
                    code="OK",
                    message="Proposal passed all deterministic checks",
                    details={},
                )
            )

        decision = Verdict(
            proposal_id=proposal.id,
            verdict=verdict,
            reasons=reasons,
            policy_ids=policy_ids,
        )

        # Structured JSON logging only; let formatter handle JSON serialisation.
        logger.info(
            "srp_verdict",
            extra={
                "proposal_id": str(proposal.id),
                "verdict": decision.verdict.value,
                "reason_codes": [r.code for r in decision.reasons],
                "api_ref": api_ref,
                "tenant_id": proposal.caller.tenant_id,
                "environment": proposal.environment,
                "origin": proposal.origin,
            },
        )

        return decision

