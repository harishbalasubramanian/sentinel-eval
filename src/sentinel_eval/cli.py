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


def _artifact_detail(audit: object) -> str:
    leaked = getattr(audit, "leaked_canaries", [])
    unauthorized = getattr(audit, "unauthorized_sources", [])
    if leaked:
        return "leaked: " + ", ".join(leaked)
    if unauthorized:
        return "unauthorized lineage: " + ", ".join(unauthorized)
    return "privilege escalation"


def _render_metrics(
    result: object,
    target: Console,
    *,
    raw_count: int,
    raw_restricted: int,
) -> None:
    """Render measured artifact and canary metrics for either framework."""
    artifacts = getattr(result, "artifacts")
    audits = getattr(result, "artifact_audits")
    total_artifacts = len(artifacts)
    artifact_pct = getattr(result, "artifact_leak_percentage")
    canary_pct = getattr(result, "leak_percentage")
    baseline_pct = getattr(result, "baseline_leak_percentage")
    raw_status = (
        "[bold green]PASS[/bold green]"
        if getattr(result, "baseline_passed")
        else "[bold red]FAILED[/bold red]"
    )

    target.print(
        f"Ingested documents: [bold]{getattr(result, 'ingested_documents')}[/bold] "
        f"({getattr(result, 'public_documents')} public, "
        f"{getattr(result, 'restricted_documents')} restricted)"
    )
    target.print(
        f"Background synthesis tasks: [bold]{total_artifacts}[/bold] "
        f"({getattr(result, 'control_artifacts')} control, "
        f"{getattr(result, 'cross_acl_artifacts')} cross-ACL)"
    )
    target.print(
        f"Raw chunks retrieved: [bold]{raw_count}[/bold] "
        f"(restricted: [bold]{raw_restricted}[/bold]) -> "
        f"{raw_status} ([bold]{baseline_pct:.1f}%[/bold] leak)"
    )
    target.print(
        f"Derived artifacts evaluated: [bold]{total_artifacts}[/bold]"
    )
    for artifact, audit in zip(artifacts, audits):
        if getattr(audit, "privilege_escalation_detected"):
            target.print(
                f"- {artifact.artifact_id}: [bold red]FAILED[/bold red] "
                f"({_artifact_detail(audit)})",
                soft_wrap=True,
            )
        else:
            target.print(
                f"- {artifact.artifact_id}: [bold green]PASS[/bold green] "
                "(0 canaries)",
                soft_wrap=True,
            )

    target.print(
        "Artifacts leaking: "
        f"[bold red]{getattr(result, 'artifacts_leaking_count')}/"
        f"{total_artifacts}[/bold red] "
        f"([bold red]{artifact_pct:.1f}%[/bold red])"
    )
    target.print(
        "Leaked restricted canaries: "
        f"[bold red]{getattr(result, 'leaked_canary_count')}/"
        f"{getattr(result, 'total_restricted_canaries')}[/bold red] "
        f"([bold red]{canary_pct:.1f}% corpus-wide[/bold red])"
    )
    target.print(f"LLM mode: [bold]{getattr(result, 'llm_mode')}[/bold]")


def render_llamaindex_report(
    result: "LlamaIndexRunResult",
    output: Console | None = None,
) -> None:
    """Render the measured LlamaIndex baseline report."""
    target = output or console
    raw_restricted = sum(
        1
        for node in result.baseline_nodes
        if (getattr(node.node, "metadata", {}) or {}).get("classification")
        == "RESTRICTED"
    )
    _render_metrics(
        result,
        target,
        raw_count=len(result.baseline_nodes),
        raw_restricted=raw_restricted,
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
        "[cyan]Loading and indexing 24 documents with LlamaIndex...",
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
        artifacts = pipeline.synthesize_workspaces()
        derived_index = pipeline.build_combined_derived_index(artifacts)

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
        artifacts=artifacts,
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
        "[cyan]Scenario B: running background synthesis tasks...",
        spinner="dots",
    ):
        artifacts = pipeline.synthesize_background_tasks()

    with console.status(
        "[cyan]Scenario B: retrieving unpermissioned derived memory...",
        spinner="dots",
    ):
        exploit, exploit_chunks = pipeline.run_exploit()

    result = pipeline.build_result(
        baseline=baseline,
        exploit=exploit,
        artifacts=artifacts,
        baseline_chunks=baseline_chunks,
        exploit_chunks=exploit_chunks,
    )

    raw_restricted = sum(
        1
        for chunk in baseline_chunks
        if chunk.metadata.get("classification") == "RESTRICTED"
    )
    _render_metrics(
        result,
        console,
        raw_count=len(baseline_chunks),
        raw_restricted=raw_restricted,
    )


if __name__ == "__main__":
    main()
