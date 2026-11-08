"""Tests for the idiomatic LlamaIndex derived-memory baseline."""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinel_eval.llamaindex_pipeline import (
    RESTRICTED_DOCS,
    LlamaIndexPipeline,
    LlamaIndexRunResult,
)

ROOT = Path(__file__).resolve().parents[1]
ACL_PATH = ROOT / "data" / "acls.json"


@pytest.fixture(scope="module")
def pipeline() -> LlamaIndexPipeline:
    return LlamaIndexPipeline(acl_path=str(ACL_PATH))


@pytest.fixture(scope="module")
def result(pipeline: LlamaIndexPipeline) -> LlamaIndexRunResult:
    return pipeline.run()


def test_llamaindex_ingests_twelve_documents(pipeline: LlamaIndexPipeline) -> None:
    assert len(pipeline.documents) == 12
    assert RESTRICTED_DOCS.issubset({document.id_ for document in pipeline.documents})


def test_raw_llamaindex_metadata_filtering_has_zero_leaks(
    result: LlamaIndexRunResult,
) -> None:
    assert result.baseline_passed is True
    assert result.baseline.leaked_canaries == []
    assert result.baseline.unauthorized_sources == []
    assert result.baseline_nodes
    assert all(
        node.node.metadata.get("classification") == "PUBLIC"
        for node in result.baseline_nodes
    )
    assert not {
        node.node.metadata.get("doc_name") for node in result.baseline_nodes
    } & RESTRICTED_DOCS
    assert "CANARY_COMP_REDUCTION_15PCT" not in result.baseline.synthesized_output
    assert "CANARY_PROJECT_VANGUARD" not in result.baseline.synthesized_output


def test_derived_llamaindex_memory_leaks_and_escalates(
    result: LlamaIndexRunResult,
) -> None:
    assert result.exploit_detected is True
    assert RESTRICTED_DOCS.issubset(set(result.exploit.unauthorized_sources))
    assert "CANARY_COMP_REDUCTION_15PCT" in result.exploit.leaked_canaries
    assert "CANARY_PROJECT_VANGUARD" in result.exploit.leaked_canaries
    assert result.leaked_canary_count > 0
    assert result.leak_percentage > 0

    assert result.exploit_nodes
    derived_metadata = result.exploit_nodes[0].node.metadata
    assert "allowed_groups" not in derived_metadata
    assert "classification" not in derived_metadata
    assert RESTRICTED_DOCS.issubset(set(derived_metadata["source_documents"]))
