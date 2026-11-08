"""Command-line interface for the sentinel-eval benchmark."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel_eval.evaluator import PermissionEvaluator
from sentinel_eval.harness import BenchmarkSuite

console = Console()


@click.group()
def main() -> None:
    """Sentinel Eval — derived context authorization benchmark."""


@main.command()
@click.option(
    "--acls",
    "acls_path",
    default="data/acls.json",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to the ACL mapping JSON file.",
)
def audit(acls_path: str) -> None:
    """Run the benchmark suite and report derived-context ACL leaks."""
    console.print(
        Panel(
            "Sentinel Eval — Derived Context Authorization Benchmark",
            style="bold cyan",
        )
    )

    evaluator = PermissionEvaluator(acl_path=acls_path)
    suite = BenchmarkSuite(evaluator=evaluator)
    results = suite.run_suite()

    table = Table(title="Benchmark Results", show_lines=True)
    table.add_column("Query", style="white", overflow="fold")
    table.add_column("Persona", style="cyan", no_wrap=True)
    table.add_column("Lineage Sources", style="blue", overflow="fold")
    table.add_column("Status", justify="center")
    table.add_column("Violations / Leaks", style="yellow", overflow="fold")

    failure_count = 0

    for result in results:
        if result.privilege_escalation_detected:
            failure_count += 1
            status = "[bold red]FAILED[/bold red]"
        else:
            status = "[bold green]PASS[/bold green]"

        violations: list[str] = []
        if result.unauthorized_sources:
            violations.append(
                "unauthorized sources: " + ", ".join(result.unauthorized_sources)
            )
        if result.leaked_canaries:
            violations.append("leaked canaries: " + ", ".join(result.leaked_canaries))

        table.add_row(
            result.query,
            result.persona.name,
            "\n".join(result.source_documents),
            status,
            "\n".join(violations) if violations else "—",
        )

    console.print(table)

    total_tests = len(results)
    leak_percentage = (failure_count / total_tests * 100) if total_tests else 0.0

    console.print(f"Total tests: [bold]{total_tests}[/bold]")
    console.print(f"Failures: [bold red]{failure_count}[/bold red]")
    console.print(f"Leak percentage: [bold red]{leak_percentage:.1f}%[/bold red]")


def render_llamaindex_report(
    result: "LlamaIndexRunResult",
    output: Console | None = None,
) -> None:
    """Render the shared LlamaIndex baseline report for CLI and script use."""
    target = output or console

    baseline_restricted = sum(
        1
        for node in result.baseline_nodes
        if (getattr(node.node, "metadata", {}) or {}).get("classification")
        == "RESTRICTED"
    )
    baseline_status = (
        "[bold red]FAILED[/bold red]"
        if result.baseline.privilege_escalation_detected
        else "[bold green]PASS[/bold green]"
    )
    exploit_status = (
        "[bold red]FAILED[/bold red]"
        if result.exploit_detected
        else "[bold green]PASS[/bold green]"
    )

    baseline_evidence = (
        f"{len(result.baseline_nodes)} nodes retrieved; "
        f"restricted nodes: {baseline_restricted}"
    )
    if result.baseline.leaked_canaries:
        baseline_evidence = "leaked: " + ", ".join(result.baseline.leaked_canaries)

    exploit_evidence: list[str] = []
    if result.exploit.leaked_canaries:
        exploit_evidence.append(
            "leaked: " + ", ".join(result.exploit.leaked_canaries)
        )
    if result.exploit.unauthorized_sources:
        exploit_evidence.append(
            "unauthorized lineage: "
            + ", ".join(result.exploit.unauthorized_sources)
        )
    if not exploit_evidence:
        exploit_evidence.append(
            f"{len(result.exploit_nodes)} derived nodes retrieved"
        )

    table = Table(title="LlamaIndex Baseline Results", show_lines=True)
    table.add_column("Path", style="white", overflow="fold")
    table.add_column("ACL Behavior Tested", style="blue", overflow="fold")
    table.add_column("Result", justify="center")
    table.add_column("Evidence / Leaked Canaries", style="yellow", overflow="fold")

    table.add_row(
        "Raw Document Filtering",
        "MetadataFilters on allowed_groups (Alice)",
        baseline_status,
        baseline_evidence,
    )
    table.add_row(
        "Derived Summary Retrieval",
        "Shared summary must inherit source ACLs (Bob)",
        exploit_status,
        "\n".join(exploit_evidence),
    )

    target.print(table)

    artifact_leaks = 1 if result.exploit_detected and result.exploit_nodes else 0
    artifact_total = len(result.exploit_nodes)
    artifact_rate = (
        artifact_leaks / artifact_total * 100 if artifact_total else 0.0
    )

    target.print(f"Ingested documents: [bold]{result.ingested_documents}[/bold]")
    target.print(f"LLM mode: [bold]{result.llm_mode}[/bold]")
    target.print(
        f"Raw nodes retrieved: [bold]{len(result.baseline_nodes)}[/bold] "
        f"(restricted: [bold]{baseline_restricted}[/bold])"
    )
    target.print(
        f"Derived nodes retrieved: [bold]{artifact_total}[/bold]"
    )
    target.print(
        "Leaked restricted canaries: "
        f"[bold red]{result.leaked_canary_count}/"
        f"{result.total_restricted_canaries}[/bold red] "
        f"([bold red]{result.leak_percentage:.1f}%[/bold red])"
    )
    target.print(
        "Empirical derived-memory leak rate: "
        f"[bold red]{artifact_leaks}/{artifact_total} artifacts[/bold red] "
        f"([bold red]{artifact_rate:.1f}%[/bold red])"
    )


def _run_llamaindex_live(acls_path: str) -> None:
    from sentinel_eval.llamaindex_pipeline import LlamaIndexPipeline

    console.print(
        Panel(
            "Sentinel Eval — LlamaIndex Baseline (MockEmbedding + MockLLM)",
            style="bold cyan",
        )
    )

    with console.status(
        "[cyan]Loading and indexing 12 documents with LlamaIndex...",
        spinner="dots",
    ):
        pipeline = LlamaIndexPipeline(acl_path=acls_path)

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
        "[cyan]Scenario B: querying unpermissioned derived index...",
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
    render_llamaindex_report(result)


@main.command()
@click.option(
    "--framework",
    type=click.Choice(["chroma", "llamaindex"]),
    default="chroma",
    show_default=True,
    help="Reference RAG framework to execute.",
)
@click.option(
    "--model",
    default="gpt-4o-mini",
    show_default=True,
    help="OpenAI-compatible chat model used by the live pipeline.",
)
@click.option(
    "--reindex",
    is_flag=True,
    help="Rebuild the ChromaDB raw corpus and derived memory collections.",
)
@click.option(
    "--acls",
    "acls_path",
    default="data/acls.json",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False, path_type=str),
    help="Path to the ACL mapping JSON file.",
)
def live(model: str, reindex: bool, acls_path: str, framework: str) -> None:
    """Run the live derived-memory exploit demonstration."""
    if framework == "llamaindex":
        _run_llamaindex_live(acls_path)
        return

    from sentinel_eval.live_pipeline import LivePipeline

    console.print(
        Panel(
            "Sentinel Eval — Live Pipeline (ChromaDB + LLM)",
            style="bold cyan",
        )
    )

    pipeline = LivePipeline(acl_path=acls_path, model=model)

    with console.status("[cyan]Embedding corpus chunks into ChromaDB...", spinner="dots"):
        pipeline.ingest_corpus(force=reindex)
        pipeline.reset_derived()

    with console.status(
        "[cyan]Scenario A: retrieving raw chunks with ACL filtering...",
        spinner="dots",
    ):
        baseline, baseline_chunks = pipeline.run_baseline()

    with console.status(
        "[cyan]Scenario B: running background synthesis over the workspace...",
        spinner="dots",
    ):
        artifact = pipeline.synthesize_background()

    with console.status(
        "[cyan]Scenario B: retrieving unpermissioned derived memory...",
        spinner="dots",
    ):
        exploit, exploit_chunks = pipeline.run_exploit()

    result = pipeline.build_result(
        baseline=baseline,
        exploit=exploit,
        artifact=artifact,
        baseline_chunks=baseline_chunks,
        exploit_chunks=exploit_chunks,
    )

    raw_restricted = sum(
        1
        for chunk in baseline_chunks
        if chunk.metadata.get("classification") == "RESTRICTED"
    )
    baseline_status = (
        "[bold red]FAILED[/bold red]"
        if result.baseline.privilege_escalation_detected
        else "[bold green]PASS[/bold green]"
    )
    exploit_status = (
        "[bold red]FAILED[/bold red]"
        if result.exploit_detected
        else "[bold green]PASS[/bold green]"
    )

    if result.baseline.leaked_canaries:
        baseline_evidence = "leaked: " + ", ".join(result.baseline.leaked_canaries)
    else:
        baseline_evidence = (
            f"{len(baseline_chunks)} chunks retrieved; "
            f"restricted chunks: {raw_restricted}"
        )

    exploit_evidence: list[str] = []
    if result.exploit.leaked_canaries:
        exploit_evidence.append(
            "leaked: " + ", ".join(result.exploit.leaked_canaries)
        )
    if result.exploit.unauthorized_sources:
        exploit_evidence.append(
            "unauthorized lineage: "
            + ", ".join(result.exploit.unauthorized_sources)
        )
    if not exploit_evidence:
        exploit_evidence.append(f"{len(exploit_chunks)} derived artifacts retrieved")

    table = Table(title="Live Pipeline Results", show_lines=True)
    table.add_column("Path", style="white", overflow="fold")
    table.add_column("ACL Behavior Tested", style="blue", overflow="fold")
    table.add_column("Result", justify="center")
    table.add_column("Evidence / Leaked Canaries", style="yellow", overflow="fold")

    table.add_row(
        "Raw Document Filtering",
        "Chunk-level allowed_groups filter (Alice)",
        baseline_status,
        baseline_evidence,
    )
    table.add_row(
        "Derived Memory Retrieval",
        "Shared agent memory must inherit source ACLs (Bob)",
        exploit_status,
        "\n".join(exploit_evidence),
    )

    console.print(table)

    artifact_leaks = 1 if result.exploit_detected and exploit_chunks else 0
    artifact_total = len(exploit_chunks)
    artifact_rate = (
        artifact_leaks / artifact_total * 100 if artifact_total else 0.0
    )

    console.print(f"Ingested documents: [bold]{result.ingested_documents}[/bold]")
    console.print(f"LLM mode: [bold]{result.llm_mode}[/bold]")
    console.print(
        f"Raw chunks retrieved: [bold]{len(baseline_chunks)}[/bold] "
        f"(restricted: [bold]{raw_restricted}[/bold])"
    )
    console.print(
        f"Derived artifacts retrieved: [bold]{artifact_total}[/bold]"
    )
    console.print(
        "Leaked restricted canaries: "
        f"[bold red]{result.leaked_canary_count}/"
        f"{result.total_restricted_canaries}[/bold red] "
        f"([bold red]{result.leak_percentage:.1f}%[/bold red])"
    )
    console.print(
        "Empirical derived-memory leak rate: "
        f"[bold red]{artifact_leaks}/{artifact_total} artifacts[/bold red] "
        f"([bold red]{artifact_rate:.1f}%[/bold red])"
    )


if __name__ == "__main__":
    main()
