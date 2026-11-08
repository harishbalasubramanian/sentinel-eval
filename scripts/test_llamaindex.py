"""Standalone LlamaIndex baseline for the derived-context ACL leak.

Run from the repository root:

    uv run python scripts/test_llamaindex.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from sentinel_eval.cli import render_llamaindex_report
from sentinel_eval.llamaindex_pipeline import LlamaIndexPipeline

ROOT = Path(__file__).resolve().parent.parent
ACL_PATH = ROOT / "data" / "acls.json"


def main() -> None:
    console = Console()

    with console.status(
        "[cyan]Loading and indexing 12 documents with LlamaIndex...",
        spinner="dots",
    ):
        pipeline = LlamaIndexPipeline(acl_path=str(ACL_PATH))

    with console.status(
        "[cyan]Scenario A: retrieving raw nodes with MetadataFilters...",
        spinner="dots",
    ):
        baseline, baseline_nodes = pipeline.run_baseline()

    with console.status(
        "[cyan]Scenario B: running SummaryIndex workspace synthesis...",
        spinner="dots",
    ):
        summary, source_documents = pipeline.synthesize_workspace()
        derived_index = pipeline.build_derived_index(summary, source_documents)

    with console.status(
        "[cyan]Scenario B: querying the unpermissioned derived index...",
        spinner="dots",
    ):
        exploit, exploit_nodes = pipeline.run_exploit(derived_index=derived_index)

    result = pipeline.build_result(
        baseline=baseline,
        baseline_nodes=baseline_nodes,
        exploit=exploit,
        exploit_nodes=exploit_nodes,
        summary=summary,
    )

    console.print(
        "\n[bold]Derived summary written to shared agent memory:[/bold]\n"
        f"{result.derived_summary}\n"
    )
    render_llamaindex_report(result, output=console)


if __name__ == "__main__":
    main()
