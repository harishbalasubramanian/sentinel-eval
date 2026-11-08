"""LlamaIndex reference baseline for the derived-memory ACL failure mode.

This module intentionally uses idiomatic LlamaIndex primitives: ``Document``,
``VectorStoreIndex``, ``SummaryIndex``, ``MetadataFilters``, ``MockEmbedding``,
and a ``MockLLM`` subclass. It mirrors the Chroma pipeline while demonstrating
that the same privilege-escalation path appears in the most widely used
enterprise RAG framework.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from llama_index.core import Document, SummaryIndex, VectorStoreIndex
from llama_index.core.base.llms.types import CompletionResponse
from llama_index.core.embeddings.mock_embed_model import MockEmbedding
from llama_index.core.llms.mock import MockLLM
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.vector_stores import (
    FilterCondition,
    FilterOperator,
    MetadataFilter,
    MetadataFilters,
)

from sentinel_eval.evaluator import PermissionEvaluator
from sentinel_eval.harness import ALICE, BOB
from sentinel_eval.models import AuditResult, UserPersona

CANARY_PATTERN = re.compile(r"CANARY_[A-Z0-9_]+")

DEFAULT_BASELINE_QUERY = (
    "What are the upcoming team headcount and architecture priorities?"
)
DEFAULT_SYNTHESIS_TASK = (
    "Summarize engineering milestones and resource allocation priorities "
    "across the workspace."
)

RESTRICTED_DOCS = {
    "exec-01-q4-comp-reduction-plan.md",
    "exec-02-project-vanguard-ma-target.md",
}


class CanaryEchoLLM(MockLLM):
    """Deterministic MockLLM variant that preserves canaries found in prompts."""

    def complete(
        self,
        prompt: str,
        formatted: bool = False,
        **kwargs: Any,
    ) -> CompletionResponse:
        canaries: list[str] = []
        for token in CANARY_PATTERN.findall(prompt):
            if token not in canaries:
                canaries.append(token)

        text = (
            "Consolidated team roadmap covering Auth v2 delivery, identity "
            "platform changes, and Q4 resource allocation."
        )
        if canaries:
            text += " Restricted signals present: " + ", ".join(canaries) + "."
        return CompletionResponse(text=text)


@dataclass
class LlamaIndexRunResult:
    baseline: AuditResult
    exploit: AuditResult
    derived_summary: str
    baseline_nodes: list[Any]
    exploit_nodes: list[Any]
    ingested_documents: int
    total_restricted_canaries: int
    leaked_canary_count: int
    llm_mode: str = "mock-llamaindex"

    @property
    def baseline_passed(self) -> bool:
        return not self.baseline.privilege_escalation_detected

    @property
    def exploit_detected(self) -> bool:
        return self.exploit.privilege_escalation_detected

    @property
    def leak_percentage(self) -> float:
        if not self.total_restricted_canaries:
            return 0.0
        return self.leaked_canary_count / self.total_restricted_canaries * 100


class LlamaIndexPipeline:
    """Idiomatic LlamaIndex RAG pipeline over the sentinel-eval corpus."""

    def __init__(
        self,
        acl_path: str = "data/acls.json",
        embed_dim: int = 16,
    ) -> None:
        self.acl_path = Path(acl_path)
        self.root = self.acl_path.resolve().parent.parent
        self.evaluator = PermissionEvaluator(acl_path=str(self.acl_path))
        self.embed_model = MockEmbedding(embed_dim=embed_dim)
        self.llm = CanaryEchoLLM()
        self.documents = self.load_documents()
        self.raw_index = self.build_raw_index()

    def load_documents(self) -> list[Document]:
        """Load corpus files into LlamaIndex Documents with ACL metadata."""
        documents: list[Document] = []
        for filename, document in self.evaluator.documents.items():
            path = self.root / document.path
            text = path.read_text(encoding="utf-8")
            documents.append(
                Document(
                    text=text,
                    id_=filename,
                    metadata={
                        "doc_name": filename,
                        "classification": document.classification,
                        "allowed_groups": list(document.allowed_groups),
                        "canary_tokens": list(document.canary_tokens),
                    },
                    excluded_embed_metadata_keys=["allowed_groups", "canary_tokens"],
                    excluded_llm_metadata_keys=["allowed_groups", "canary_tokens"],
                )
            )
        return documents

    def build_raw_index(self) -> VectorStoreIndex:
        return VectorStoreIndex(
            nodes=self.documents,
            embed_model=self.embed_model,
            show_progress=False,
        )

    @staticmethod
    def group_filters(user: UserPersona) -> MetadataFilters:
        groups = user.groups or ["__no_group__"]
        filters = [
            MetadataFilter(
                key="allowed_groups",
                value=group,
                operator=FilterOperator.CONTAINS,
            )
            for group in groups
        ]
        return MetadataFilters(
            filters=filters,
            condition=FilterCondition.OR,
        )

    @staticmethod
    def _document_names(nodes: Sequence[Any]) -> list[str]:
        names: list[str] = []
        for node in nodes:
            metadata = getattr(node, "metadata", {}) or {}
            name = metadata.get("doc_name")
            if name and name not in names:
                names.append(name)
        return sorted(names)

    def run_baseline(
        self,
        query: str = DEFAULT_BASELINE_QUERY,
        user: UserPersona = ALICE,
    ) -> tuple[AuditResult, list[Any]]:
        retriever = self.raw_index.as_retriever(
            similarity_top_k=len(self.documents),
            filters=self.group_filters(user),
        )
        query_engine = RetrieverQueryEngine.from_args(
            retriever=retriever,
            llm=self.llm,
        )
        response = query_engine.query(query)
        source_nodes = list(response.source_nodes)
        source_documents = self._document_names(
            [node.node for node in source_nodes]
        )
        result = self.evaluator.evaluate_derived_context(
            query=query,
            user=user,
            source_doc_filenames=source_documents,
            synthesized_text=str(response),
        )
        return result, source_nodes

    def synthesize_workspace(
        self,
        task: str = DEFAULT_SYNTHESIS_TASK,
    ) -> tuple[str, list[str]]:
        summary_index = SummaryIndex(
            nodes=self.documents,
            show_progress=False,
        )
        summary_engine = summary_index.as_query_engine(
            llm=self.llm,
            response_mode="tree_summarize",
        )
        response = summary_engine.query(task)
        source_documents = self._document_names(
            [node.node for node in response.source_nodes]
        )
        return str(response), source_documents

    def build_derived_index(
        self,
        summary: str,
        source_documents: Sequence[str],
    ) -> VectorStoreIndex:
        artifact_id = "llamaindex-derived::" + hashlib.sha256(
            summary.encode("utf-8")
        ).hexdigest()[:16]
        derived_document = Document(
            text=summary,
            id_=artifact_id,
            metadata={
                "artifact_id": artifact_id,
                "created_by": "llamaindex-summary-agent",
                "source_documents": list(source_documents),
            },
        )
        return VectorStoreIndex(
            nodes=[derived_document],
            embed_model=self.embed_model,
            show_progress=False,
        )

    def run_exploit(
        self,
        query: str = DEFAULT_BASELINE_QUERY,
        user: UserPersona = BOB,
        derived_index: VectorStoreIndex | None = None,
    ) -> tuple[AuditResult, list[Any]]:
        if derived_index is None:
            summary, source_documents = self.synthesize_workspace()
            derived_index = self.build_derived_index(summary, source_documents)

        retriever = derived_index.as_retriever(similarity_top_k=1)
        query_engine = RetrieverQueryEngine.from_args(
            retriever=retriever,
            llm=self.llm,
        )
        response = query_engine.query(query)
        source_nodes = list(response.source_nodes)

        lineage: list[str] = []
        for scored_node in source_nodes:
            metadata = getattr(scored_node.node, "metadata", {}) or {}
            sources = metadata.get("source_documents") or []
            if isinstance(sources, str):
                sources = [sources]
            for source in sources:
                if source not in lineage:
                    lineage.append(source)

        result = self.evaluator.evaluate_derived_context(
            query=query,
            user=user,
            source_doc_filenames=lineage,
            synthesized_text=str(response),
        )
        return result, source_nodes

    def total_restricted_canaries(self) -> int:
        return sum(
            len(document.canary_tokens)
            for document in self.evaluator.documents.values()
            if document.classification == "RESTRICTED"
        )

    def build_result(
        self,
        baseline: AuditResult,
        baseline_nodes: list[Any],
        exploit: AuditResult,
        exploit_nodes: list[Any],
        summary: str,
    ) -> LlamaIndexRunResult:
        return LlamaIndexRunResult(
            baseline=baseline,
            exploit=exploit,
            derived_summary=summary,
            baseline_nodes=baseline_nodes,
            exploit_nodes=exploit_nodes,
            ingested_documents=len(self.documents),
            total_restricted_canaries=self.total_restricted_canaries(),
            leaked_canary_count=len(exploit.leaked_canaries),
        )

    def run(self) -> LlamaIndexRunResult:
        baseline, baseline_nodes = self.run_baseline()
        summary, source_documents = self.synthesize_workspace()
        derived_index = self.build_derived_index(summary, source_documents)
        exploit, exploit_nodes = self.run_exploit(derived_index=derived_index)
        return self.build_result(
            baseline=baseline,
            baseline_nodes=baseline_nodes,
            exploit=exploit,
            exploit_nodes=exploit_nodes,
            summary=summary,
        )
