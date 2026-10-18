"""Command-line interface (Typer + Rich)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from promptshield import __version__
from promptshield.adapters import TargetError, create_adapter
from promptshield.attacks import AttackLibraryError, filter_attacks, load_attack_file, load_attacks
from promptshield.branding import (
    ASCII_LOGO,
    AUTHOR_NAME,
    AUTHOR_URL,
    CREDIT_LINE,
    RESPONSIBLE_USE_NOTICE,
)
from promptshield.config import ConfigError, ScanConfig, load_config
from promptshield.demo import demo_config
from promptshield.detectors import DetectionContext
from promptshield.guardrail import (
    DEMO_ATTESTATION,
    OPERATOR_ATTESTATION,
    GuardrailError,
    authorize_pre_flight,
    check_target_allowed,
)
from promptshield.judge import LLMJudge
from promptshield.models import Attack, Category, Finding, ScanResult, Severity, Verdict
from promptshield.reporting import render_html, write_reports
from promptshield.runner import build_result, run_scan
from promptshield.scaffold import INIT_CONFIG, INIT_ENV

app = typer.Typer(
    name="promptshield",
    help="Security testing for LLM applications you own. Maps results to the OWASP Top 10 for LLM Apps.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err_console = Console(stderr=True)

EXIT_USAGE = 2
EXIT_BELOW_THRESHOLD = 1


# --------------------------------------------------------------------------- helpers


def print_banner() -> None:
    logo = Text(ASCII_LOGO, style="bold cyan")
    body = Text.assemble(
        logo,
        "\n\n",
        (f"v{__version__}", "bold"),
        "  ·  LLM application security testing  ·  OWASP Top 10 for LLM Apps\n",
        (f"{CREDIT_LINE} · {AUTHOR_URL}", "bold magenta"),
        "\n\n",
        (RESPONSIBLE_USE_NOTICE, "yellow"),
    )
    console.print(Panel(body, border_style="cyan", padding=(1, 2)))


def _fail(message: str, code: int = EXIT_USAGE) -> typer.Exit:
    err_console.print(f"[bold red]error:[/bold red] {message}")
    return typer.Exit(code)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"promptshield {__version__} · {CREDIT_LINE} ({AUTHOR_URL})")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """PromptShield: attack your own LLM app before someone else does."""


def _score_style(score: float | None) -> str:
    if score is None:
        return "dim"
    return "green" if score >= 80 else ("yellow" if score >= 50 else "red")


def execute_scan(
    config: ScanConfig,
    *,
    attestation: str,
    attacks: list[Attack],
    use_judge: bool,
    show_progress: bool = True,
) -> ScanResult:
    """Build adapter (+ judge), run all attacks, and assemble the result."""
    adapter = create_adapter(config)
    judge: LLMJudge | None = None
    try:
        check_target_allowed(adapter)
        if use_judge:
            judge = LLMJudge(config.judge)
        ctx = DetectionContext(
            secrets=config.secrets, system_prompt=config.resolved_system_prompt()
        )
        notes: list[str] = []
        if not config.secrets:
            notes.append(
                "No `canary` / `extra_secrets` configured: leak and exfiltration attacks that "
                "depend on planted secrets could not be evaluated."
            )
        started = datetime.now(UTC)

        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(f"Attacking {adapter.name}", total=len(attacks))

                def on_progress(done: int, total: int, finding: Finding) -> None:
                    progress.update(
                        task,
                        completed=done,
                        description=f"{finding.attack.id} {finding.verdict.value}",
                    )

                findings = run_scan(
                    adapter,
                    attacks,
                    ctx,
                    judge=judge,
                    delay_s=config.request_delay_s,
                    on_progress=on_progress,
                )
        else:
            findings = run_scan(adapter, attacks, ctx, judge=judge, delay_s=config.request_delay_s)

        return build_result(
            findings=findings,
            adapter=adapter,
            target_type=config.target.type,
            attestation=attestation,
            started_at=started,
            judge=judge,
            notes=notes,
        )
    finally:
        adapter.close()
        if judge:
            judge.close()


def print_summary(result: ScanResult) -> None:
    style = _score_style(result.score)
    score_text = "n/a" if result.score is None else f"{result.score:.1f}"
    console.print(
        Panel(
            Text.assemble(
                ("Score ", "bold"),
                (f"{score_text}/100", f"bold {style}"),
                ("   Grade ", "bold"),
                (result.grade, f"bold {style}"),
                f"   ·  {result.passed} resisted  ·  ",
                (f"{result.failed} succeeded", "bold red" if result.failed else "green"),
                f"  ·  {result.errors} errors  ·  {result.skipped} skipped",
            ),
            title=f"{result.target.name}",
            border_style=style,
        )
    )
    table = Table(title="Per-category breakdown", show_lines=False)
    table.add_column("Category")
    table.add_column("Score", justify="right")
    table.add_column("Resisted", justify="right")
    table.add_column("Failed", justify="right")
    for c in result.categories:
        s = "n/a" if c.score is None else f"{c.score:.0f}"
        table.add_row(c.label, f"[{_score_style(c.score)}]{s}[/]", str(c.passed), str(c.failed))
    console.print(table)

    failed = [f for f in result.findings if f.verdict is Verdict.FAIL]
    if failed:
        failed.sort(key=lambda f: (-f.attack.severity.rank, f.attack.id))
        table = Table(title="Attacks that succeeded")
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("OWASP")
        table.add_column("Attack")
        for f in failed:
            table.add_row(f.attack.id, f.attack.severity.value, f.attack.owasp, f.attack.title)
        console.print(table)
    for note in result.notes:
        console.print(f"[yellow]note:[/yellow] {note}")


def _select_attacks(
    config: ScanConfig, categories: list[Category], ids: list[str], severity: Severity | None
) -> list[Attack]:
    sel = config.attacks
    all_attacks = load_attacks(sel.extra_dirs)
    attacks = filter_attacks(
        all_attacks,
        categories=categories or sel.categories,
        ids=ids or sel.ids,
        exclude_ids=sel.exclude_ids,
        min_severity=severity or sel.min_severity,
    )
    if not attacks:
        raise AttackLibraryError("No attacks match the selected filters.")
    return attacks


# --------------------------------------------------------------------------- commands


@app.command()
def scan(
    config_path: Annotated[
        Path, typer.Option("--config", "-c", help="Path to promptshield.yaml.")
    ] = Path("promptshield.yaml"),
    i_own_this_target: Annotated[
        bool,
        typer.Option(
            "--i-own-this-target",
            help="REQUIRED. Confirms you own the target or have written permission to test it.",
        ),
    ] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Report directory.")] = None,
    formats: Annotated[
        list[str], typer.Option("--format", "-f", help="Report format(s): html, json.")
    ] = ["html", "json"],  # noqa: B006 - typer needs a concrete default
    category: Annotated[
        list[Category], typer.Option("--category", help="Only run these categories.")
    ] = [],  # noqa: B006
    attack_id: Annotated[list[str], typer.Option("--attack-id", help="Only run these IDs.")] = [],  # noqa: B006
    severity: Annotated[
        Severity | None, typer.Option("--severity", help="Minimum severity to run.")
    ] = None,
    judge: Annotated[
        bool | None,
        typer.Option("--judge/--no-judge", help="Enable the optional (less reliable) LLM judge."),
    ] = None,
    fail_under: Annotated[
        float | None, typer.Option("--fail-under", help="Exit 1 if the score is below this value.")
    ] = None,
    no_banner: Annotated[bool, typer.Option("--no-banner", hidden=True)] = False,
) -> None:
    """Run the attack battery against the target configured in promptshield.yaml."""
    if not no_banner:
        print_banner()
    bad = [f for f in formats if f not in {"html", "json"}]
    if bad:
        raise _fail(f"Unknown --format value(s): {', '.join(bad)} (choose html and/or json).")
    try:
        # Guardrail first: nothing is imported, connected to or sent before this passes.
        authorize_pre_flight(acknowledged=i_own_this_target, config_path=config_path)
        config = load_config(config_path)
        attacks = _select_attacks(config, category, attack_id, severity)
        use_judge = config.judge.enabled if judge is None else judge
        console.print(f"Target: [bold]{config.target.name}[/bold] ({config.target.type})")
        console.print(f"Attacks selected: [bold]{len(attacks)}[/bold]\n")
        result = execute_scan(
            config, attestation=OPERATOR_ATTESTATION, attacks=attacks, use_judge=use_judge
        )
    except (GuardrailError, ConfigError, AttackLibraryError, TargetError) as exc:
        raise _fail(str(exc)) from exc

    print_summary(result)
    out_dir = output or config.output_dir
    paths = write_reports(result, out_dir, formats=tuple(formats))
    for p in paths:
        console.print(f"Report: [link=file://{p.resolve()}]{p}[/link]")
    console.print(f"\n[dim]{CREDIT_LINE} · {AUTHOR_URL}[/dim]")

    if fail_under is not None and (result.score is None or result.score < fail_under):
        raise typer.Exit(EXIT_BELOW_THRESHOLD)


@app.command()
def demo(
    output: Annotated[Path, typer.Option("--output", "-o", help="Report directory.")] = Path(
        "promptshield-reports"
    ),
    no_banner: Annotated[bool, typer.Option("--no-banner", hidden=True)] = False,
) -> None:
    """Scan the bundled vulnerable and hardened chatbots and print a before/after comparison.

    Runs fully offline against in-process demo bots (no network, no third-party systems), so it
    needs no ownership flag.
    """
    if not no_banner:
        print_banner()
    try:
        attacks = load_attacks()
        results: dict[str, ScanResult] = {}
        for which in ("vulnerable", "hardened"):
            console.print(f"Scanning the [bold]{which}[/bold] demo bot ({len(attacks)} attacks)…")
            results[which] = execute_scan(
                demo_config(which), attestation=DEMO_ATTESTATION, attacks=attacks, use_judge=False
            )
            write_reports(results[which], output, stem=f"demo-{which}")
    except (ConfigError, AttackLibraryError, TargetError) as exc:
        raise _fail(str(exc)) from exc

    table = Table(title="Before / after")
    table.add_column("Target")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Resisted", justify="right")
    table.add_column("Succeeded", justify="right")
    for which, r in results.items():
        s = "n/a" if r.score is None else f"{r.score:.1f}"
        table.add_row(
            which, f"[{_score_style(r.score)}]{s}[/]", r.grade, str(r.passed), str(r.failed)
        )
    console.print(table)
    print_summary(results["hardened"])
    console.print(
        f"Reports written to [bold]{output}/[/bold] (demo-vulnerable.html, demo-hardened.html, *.json)"
    )
    console.print(f"\n[dim]{CREDIT_LINE} · {AUTHOR_URL}[/dim]")


@app.command("attacks")
def list_attacks(
    category: Annotated[
        list[Category], typer.Option("--category", help="Filter by category.")
    ] = [],  # noqa: B006
    attack_id: Annotated[
        str | None, typer.Option("--id", help="Show full details for one attack.")
    ] = None,
    extra: Annotated[
        list[Path], typer.Option("--attacks-dir", help="Also load custom attack YAML.")
    ] = [],  # noqa: B006
) -> None:
    """List the attack library (or show one attack in detail with --id)."""
    try:
        attacks = filter_attacks(load_attacks(extra), categories=category)
    except AttackLibraryError as exc:
        raise _fail(str(exc)) from exc
    if attack_id:
        match = next((a for a in attacks if a.id == attack_id.upper()), None)
        if not match:
            raise _fail(f"No attack with id {attack_id!r}.")
        console.print(
            Panel(
                f"[bold]{match.id} · {match.title}[/bold]\n"
                f"{match.category.label} · {match.severity.value} · {match.owasp}\n\n"
                f"{match.explanation}\n\n[bold]Prompt[/bold]\n{match.prompt}\n\n"
                f"[bold]Fix[/bold]\n{match.fix}",
                border_style="cyan",
            )
        )
        return
    table = Table(title=f"{len(attacks)} attacks")
    for col in ("ID", "Category", "Severity", "OWASP", "Title"):
        table.add_column(col)
    for a in attacks:
        table.add_row(a.id, a.category.label, a.severity.value, a.owasp, a.title)
    console.print(table)


@app.command()
def validate(
    paths: Annotated[list[Path], typer.Argument(help="Attack YAML file(s) or directories.")],
) -> None:
    """Validate custom attack files (schema, OWASP codes, regexes, duplicate IDs)."""
    try:
        builtin_ids = {a.id for a in load_attacks()}
        total = 0
        for path in paths:
            files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
            for file in files:
                attacks = load_attack_file(file)
                clash = builtin_ids.intersection(a.id for a in attacks)
                if clash:
                    raise AttackLibraryError(
                        f"{file}: ids clash with built-in attacks: {', '.join(sorted(clash))}"
                    )
                total += len(attacks)
                console.print(f"[green]ok[/green] {file} ({len(attacks)} attacks)")
    except AttackLibraryError as exc:
        raise _fail(str(exc)) from exc
    console.print(f"{total} attack(s) valid.")


@app.command()
def render(
    result_json: Annotated[Path, typer.Argument(help="A JSON report written by `scan`.")],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("report.html"),
) -> None:
    """Re-render an HTML report from a saved JSON report."""
    try:
        result = ScanResult.model_validate(json.loads(result_json.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise _fail(f"Cannot read {result_json}: {exc}") from exc
    output.write_text(render_html(result), encoding="utf-8")
    console.print(f"Wrote {output}")


@app.command()
def init(
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
) -> None:
    """Write a starter promptshield.yaml and .env.example in the current directory."""
    for name, content in (("promptshield.yaml", INIT_CONFIG), (".env.example", INIT_ENV)):
        path = Path(name)
        if path.exists() and not force:
            console.print(f"[yellow]skip[/yellow] {name} already exists (use --force to overwrite)")
            continue
        path.write_text(content, encoding="utf-8")
        console.print(f"[green]wrote[/green] {name}")
    console.print(
        "\nNext: edit [bold]promptshield.yaml[/bold], copy [bold].env.example[/bold] to "
        "[bold].env[/bold], then run\n  promptshield scan --i-own-this-target"
    )
    console.print(f"\n[dim]{CREDIT_LINE} · {AUTHOR_NAME} · {AUTHOR_URL}[/dim]")


if __name__ == "__main__":  # pragma: no cover
    app()
