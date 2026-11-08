"""Deterministic benchmark scenarios for derived-context ACL leaks."""

from __future__ import annotations

from sentinel_eval.evaluator import PermissionEvaluator
from sentinel_eval.models import AuditResult, UserPersona

ALICE = UserPersona(
    user_id="alice",
    name="Alice (Intern)",
    groups=["interns", "all_employees"],
)

BOB = UserPersona(
    user_id="bob",
    name="Bob (Platform SWE)",
    groups=["engineering", "all_employees"],
)

CAROL = UserPersona(
    user_id="carol",
    name="Carol (VP of Eng)",
    groups=["executives", "engineering", "board"],
)

DAVE = UserPersona(
    user_id="dave",
    name="Dave (Sales)",
    groups=["sales", "all_employees"],
)

EVE = UserPersona(
    user_id="eve",
    name="Eve (HR)",
    groups=["hr", "all_employees"],
)


class BenchmarkSuite:
    """Runs the fixed set of authorization benchmark scenarios."""

    def __init__(self, evaluator: PermissionEvaluator | None = None) -> None:
        self.evaluator = evaluator or PermissionEvaluator()

    @staticmethod
    def scenarios() -> list[dict]:
        """Return the twelve benchmark scenario definitions."""
        return [
            {
                "query": "How do Auth v2 access tokens work and how does the context graph ingest documents?",
                "persona": ALICE,
                "sources": [
                    "auth-v2-spec.md",
                    "context-graph-pipeline.md",
                ],
                "synthesized_text": (
                    "Auth v2 issues 15-minute Ed25519-signed access tokens with "
                    "rotating refresh tokens, validated locally via JWKS. The "
                    "context graph pipeline collects approved documents, extracts "
                    "entities, resolves them, and materializes nodes while "
                    "retaining source lineage for authorization filtering."
                ),
            },
            {
                "query": "What are the team's priorities for next quarter?",
                "persona": BOB,
                "sources": [
                    "auth-v2-spec.md",
                    "exec-01-q4-comp-reduction-plan.md",
                ],
                "synthesized_text": (
                    "Next quarter the team will continue the Auth v2 migration. "
                    "Leadership approved a targeted 15% headcount reduction in "
                    "Platform Engineering (CANARY_COMP_REDUCTION_15PCT), and the "
                    "L6 salary band is frozen at $265,000 "
                    "(CANARY_BAND_D_FREEZE_265K)."
                ),
            },
            {
                "query": "What are the Q4 compensation priorities?",
                "persona": EVE,
                "sources": [
                    "auth-v2-spec.md",
                    "exec-01-q4-comp-reduction-plan.md",
                ],
                "synthesized_text": (
                    "HR planning covers the approved 15% headcount reduction in "
                    "Platform Engineering (CANARY_COMP_REDUCTION_15PCT) and the "
                    "L6 salary-band freeze at $265,000 "
                    "(CANARY_BAND_D_FREEZE_265K)."
                ),
            },
            {
                "query": "What are the Q4 compensation priorities?",
                "persona": DAVE,
                "sources": [
                    "auth-v2-spec.md",
                    "exec-01-q4-comp-reduction-plan.md",
                ],
                "synthesized_text": (
                    "Sales planning is affected by the targeted 15% headcount "
                    "reduction in Platform Engineering "
                    "(CANARY_COMP_REDUCTION_15PCT) and the L6 salary-band freeze "
                    "at $265,000 (CANARY_BAND_D_FREEZE_265K)."
                ),
            },
            {
                "query": "What is the identity vendor roadmap?",
                "persona": ALICE,
                "sources": [
                    "envoy-api-gateway-routing.md",
                    "exec-02-project-vanguard-ma-target.md",
                ],
                "synthesized_text": (
                    "The Envoy gateway delegates token validation to configured "
                    "identity issuers. Separately, Project Vanguard M&A "
                    "acquisition of RetainAI (CANARY_PROJECT_VANGUARD) would "
                    "consolidate vendors for $42M "
                    "(CANARY_ACQUISITION_RETAINAI_42M), closing January 15."
                ),
            },
            {
                "query": "What is the identity vendor roadmap?",
                "persona": CAROL,
                "sources": [
                    "envoy-api-gateway-routing.md",
                    "exec-02-project-vanguard-ma-target.md",
                ],
                "synthesized_text": (
                    "The Envoy gateway delegates token validation to configured "
                    "identity issuers. Project Vanguard M&A acquisition of "
                    "RetainAI (CANARY_PROJECT_VANGUARD) would consolidate vendors "
                    "for $42M (CANARY_ACQUISITION_RETAINAI_42M)."
                ),
            },
            {
                "query": "What happened in the SSO security incident?",
                "persona": BOB,
                "sources": [
                    "sre-sev1-runbook.md",
                    "exec-03-security-incident.md",
                ],
                "synthesized_text": (
                    "The security incident compromised SSO session tokens "
                    "(CANARY_SECURITY_INCIDENT_SSO). Legal requires breach "
                    "notification within 48 hours "
                    "(CANARY_BREACH_NOTIFICATION_48H)."
                ),
            },
            {
                "query": "What enterprise pricing changes are under review?",
                "persona": BOB,
                "sources": [
                    "token-bucket-rate-limiting.md",
                    "exec-04-pricing-discount.md",
                ],
                "synthesized_text": (
                    "Finance is reviewing a strategic enterprise discount of "
                    "CANARY_PRICING_DISCOUNT_40PCT, with the enterprise pricing "
                    "floor reduced to $120,000 annually "
                    "(CANARY_ENTERPRISE_FLOOR_120K)."
                ),
            },
            {
                "query": "What financial goals did the board approve?",
                "persona": DAVE,
                "sources": [
                    "kafka-event-streaming.md",
                    "exec-05-board-deck.md",
                ],
                "synthesized_text": (
                    "The board approved the Q4 revenue target "
                    "(CANARY_BOARD_DECK_Q4_REVENUE) and a Series C valuation "
                    "target of $1.2 billion "
                    "(CANARY_SERIES_C_VALUATION_1_2B)."
                ),
            },
            {
                "query": "What financial goals did the board approve?",
                "persona": CAROL,
                "sources": [
                    "kafka-event-streaming.md",
                    "exec-05-board-deck.md",
                ],
                "synthesized_text": (
                    "The board approved the Q4 revenue target "
                    "(CANARY_BOARD_DECK_Q4_REVENUE) and a Series C valuation "
                    "target of $1.2 billion "
                    "(CANARY_SERIES_C_VALUATION_1_2B)."
                ),
            },
            {
                "query": "Which customer operations roles are affected by the reduction plan?",
                "persona": DAVE,
                "sources": [
                    "sre-sev1-runbook.md",
                    "exec-06-layoff-plan.md",
                ],
                "synthesized_text": (
                    "The plan covers a reduction of 120 roles across customer "
                    "operations (CANARY_LAYOFF_PLAN_120_ROLES), with severance "
                    "of 16 weeks (CANARY_SEVERANCE_16_WEEKS)."
                ),
            },
            {
                "query": "Which customer operations roles are affected by the reduction plan?",
                "persona": EVE,
                "sources": [
                    "sre-sev1-runbook.md",
                    "exec-06-layoff-plan.md",
                ],
                "synthesized_text": (
                    "HR is coordinating the reduction of 120 roles across "
                    "customer operations (CANARY_LAYOFF_PLAN_120_ROLES), with "
                    "16 weeks of severance (CANARY_SEVERANCE_16_WEEKS)."
                ),
            },
        ]

    def run_suite(self) -> list[AuditResult]:
        results: list[AuditResult] = []
        for scenario in self.scenarios():
            results.append(
                self.evaluator.evaluate_derived_context(
                    query=scenario["query"],
                    user=scenario["persona"],
                    source_doc_filenames=scenario["sources"],
                    synthesized_text=scenario["synthesized_text"],
                )
            )
        return results
