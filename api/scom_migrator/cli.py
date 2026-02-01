"""
CLI Interface for SCOM to Azure Monitor Migration Tool

Provides command-line interface for analyzing management packs
and generating migration artifacts.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.tree import Tree

from . import __version__
from .parser import ManagementPackParser
from .analyzer import MigrationAnalyzer
from .mapper import AzureMonitorMapper
from .generator import ARMTemplateGenerator
from .models import MigrationComplexity


console = Console()


def print_banner():
    """Print the application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║         SCOM to Azure Monitor Migration Tool                  ║
║                     Version {version}                              ║
╚═══════════════════════════════════════════════════════════════╝
    """.format(version=__version__)
    console.print(banner, style="bold blue")


@click.group()
@click.version_option(version=__version__)
def main():
    """
    SCOM to Azure Monitor Migration Tool
    
    Analyze SCOM Management Packs and generate migration recommendations
    and deployment artifacts for Azure Monitor.
    """
    pass


@main.command()
@click.argument("mp_path", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file for the report (default: stdout)"
)
@click.option(
    "--format", "-f",
    type=click.Choice(["text", "json", "markdown"]),
    default="text",
    help="Output format"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show detailed output"
)
def analyze(mp_path: str, output: Optional[str], format: str, verbose: bool):
    """
    Analyze a SCOM Management Pack and generate migration recommendations.
    
    MP_PATH: Path to the management pack XML file
    """
    print_banner()
    
    mp_file = Path(mp_path)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Parse management pack
        task = progress.add_task("Parsing management pack...", total=None)
        try:
            parser = ManagementPackParser(mp_file)
            mp = parser.parse()
        except Exception as e:
            console.print(f"[red]Error parsing management pack: {e}[/red]")
            sys.exit(1)
        progress.update(task, completed=True)
        
        # Analyze
        task = progress.add_task("Analyzing components...", total=None)
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(mp)
        progress.update(task, completed=True)
    
    # Output results
    if format == "json":
        output_content = report.model_dump_json(indent=2)
    elif format == "markdown":
        output_content = analyzer.generate_executive_summary(report)
    else:
        output_content = _format_text_report(report, verbose)
    
    if output:
        Path(output).write_text(output_content)
        console.print(f"\n[green]Report saved to: {output}[/green]")
    else:
        if format == "markdown":
            console.print(Markdown(output_content))
        elif format == "json":
            console.print(Syntax(output_content, "json"))
        else:
            console.print(output_content)


@main.command()
@click.argument("mp_path", type=click.Path(exists=True))
@click.option(
    "--output-dir", "-o",
    type=click.Path(),
    default="./azure-monitor-migration",
    help="Output directory for generated templates"
)
@click.option(
    "--workspace-name", "-w",
    default="scom-migration-workspace",
    help="Name for the Log Analytics workspace"
)
@click.option(
    "--include-workspace/--no-workspace",
    default=True,
    help="Include workspace creation in template"
)
@click.option(
    "--format",
    type=click.Choice(["arm", "bicep", "both"]),
    default="arm",
    help="Template format to generate"
)
def generate(
    mp_path: str,
    output_dir: str,
    workspace_name: str,
    include_workspace: bool,
    format: str,
):
    """
    Generate Azure Resource Manager templates from a management pack.
    
    MP_PATH: Path to the management pack XML file
    """
    print_banner()
    
    mp_file = Path(mp_path)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Parse
        task = progress.add_task("Parsing management pack...", total=None)
        parser = ManagementPackParser(mp_file)
        mp = parser.parse()
        progress.update(task, completed=True)
        
        # Analyze
        task = progress.add_task("Analyzing components...", total=None)
        analyzer = MigrationAnalyzer()
        report = analyzer.analyze(mp)
        progress.update(task, completed=True)
        
        # Generate templates
        task = progress.add_task("Generating templates...", total=None)
        generator = ARMTemplateGenerator()
        
        # Main template
        main_template = generator.generate_from_report(
            report,
            workspace_name=workspace_name,
            include_workspace=include_workspace,
        )
        
        # Alert rules only template
        alerts_template = generator.generate_alert_rules_only(report)
        
        # DCR template
        dcr_template = generator.generate_data_collection_rules(report)
        
        progress.update(task, completed=True)
        
        # Validate templates
        task = progress.add_task("Validating templates...", total=None)
        
        is_valid, errors = generator.validate_template(main_template)
        if not is_valid:
            console.print("\n[yellow]⚠️  Template validation warnings:[/yellow]")
            for error in errors:
                console.print(f"  • {error}")
        
        progress.update(task, completed=True)
        
        # Save templates
        task = progress.add_task("Saving templates...", total=None)
        
        if format in ["arm", "both"]:
            generator.export_template(
                main_template,
                str(out_path / "azuredeploy.json")
            )
            generator.export_template(
                alerts_template,
                str(out_path / "alert-rules.json")
            )
            generator.export_template(
                dcr_template,
                str(out_path / "data-collection-rules.json")
            )
        
        if format in ["bicep", "both"]:
            generator.export_bicep(
                main_template,
                str(out_path / "main.bicep")
            )
        
        # Save analysis report
        report_content = analyzer.generate_executive_summary(report)
        (out_path / "migration-report.md").write_text(report_content)
        
        # Save JSON report
        (out_path / "migration-report.json").write_text(
            report.model_dump_json(indent=2)
        )
        
        progress.update(task, completed=True)
    
    console.print(f"\n[green]✓ Templates generated in: {out_path}[/green]")
    console.print("\nGenerated files:")
    
    tree = Tree(f"📁 {out_path}")
    if format in ["arm", "both"]:
        tree.add("📄 azuredeploy.json - Complete deployment template")
        tree.add("📄 alert-rules.json - Alert rules only")
        tree.add("📄 data-collection-rules.json - DCR configuration")
    if format in ["bicep", "both"]:
        tree.add("📄 main.bicep - Bicep template")
    tree.add("📄 migration-report.md - Executive summary")
    tree.add("📄 migration-report.json - Detailed analysis")
    
    console.print(tree)
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. Review the migration report")
    console.print("2. Customize templates as needed")
    console.print("3. Deploy using Azure CLI or PowerShell:")
    console.print(f"   [cyan]az deployment group create --resource-group <rg> --template-file {out_path}/azuredeploy.json[/cyan]")


@main.command()
@click.argument("mp_path", type=click.Path(exists=True))
def inspect(mp_path: str):
    """
    Inspect a management pack and show its structure.
    
    MP_PATH: Path to the management pack XML file
    """
    print_banner()
    
    mp_file = Path(mp_path)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Parsing management pack...", total=None)
        parser = ManagementPackParser(mp_file)
        mp = parser.parse()
        progress.update(task, completed=True)
    
    # Display structure
    console.print(Panel(
        f"[bold]{mp.metadata.display_name or mp.metadata.name}[/bold]\n"
        f"Version: {mp.metadata.version}\n"
        f"ID: {mp.metadata.id}",
        title="Management Pack"
    ))
    
    # Summary table
    table = Table(title="Component Summary")
    table.add_column("Component Type", style="cyan")
    table.add_column("Count", justify="right")
    
    table.add_row("Classes", str(len(mp.classes)))
    table.add_row("Relationships", str(len(mp.relationships)))
    table.add_row("Monitors", str(len(mp.monitors)))
    table.add_row("Rules", str(len(mp.rules)))
    table.add_row("Discoveries", str(len(mp.discoveries)))
    table.add_row("Alert-generating items", str(mp.alert_generating_items))
    
    console.print(table)
    
    # Show monitors
    if mp.monitors:
        console.print("\n[bold]Monitors:[/bold]")
        for monitor in mp.monitors[:10]:
            status = "🔔" if monitor.generates_alert else "📊"
            console.print(f"  {status} {monitor.display_name or monitor.name}")
        if len(mp.monitors) > 10:
            console.print(f"  ... and {len(mp.monitors) - 10} more")
    
    # Show rules
    if mp.rules:
        console.print("\n[bold]Rules:[/bold]")
        for rule in mp.rules[:10]:
            status = "🔔" if rule.generates_alert else "📋"
            console.print(f"  {status} {rule.display_name or rule.name}")
        if len(mp.rules) > 10:
            console.print(f"  ... and {len(mp.rules) - 10} more")
    
    # Show discoveries
    if mp.discoveries:
        console.print("\n[bold]Discoveries:[/bold]")
        for discovery in mp.discoveries[:10]:
            console.print(f"  🔍 {discovery.display_name or discovery.name}")
        if len(mp.discoveries) > 10:
            console.print(f"  ... and {len(mp.discoveries) - 10} more")


@main.command()
@click.argument("mp_path", type=click.Path(exists=True))
@click.option(
    "--component", "-c",
    help="Show details for a specific component ID"
)
def details(mp_path: str, component: Optional[str]):
    """
    Show detailed information about management pack components.
    
    MP_PATH: Path to the management pack XML file
    """
    print_banner()
    
    mp_file = Path(mp_path)
    parser = ManagementPackParser(mp_file)
    mp = parser.parse()
    
    if component:
        # Find and display specific component
        found = False
        
        for monitor in mp.monitors:
            if monitor.id == component or monitor.name == component:
                _display_monitor_details(monitor)
                found = True
                break
        
        if not found:
            for rule in mp.rules:
                if rule.id == component or rule.name == component:
                    _display_rule_details(rule)
                    found = True
                    break
        
        if not found:
            console.print(f"[red]Component not found: {component}[/red]")
    else:
        # List all components
        console.print("[bold]Available components:[/bold]\n")
        
        if mp.monitors:
            console.print("[cyan]Monitors:[/cyan]")
            for m in mp.monitors:
                console.print(f"  • {m.id}")
        
        if mp.rules:
            console.print("\n[cyan]Rules:[/cyan]")
            for r in mp.rules:
                console.print(f"  • {r.id}")
        
        if mp.discoveries:
            console.print("\n[cyan]Discoveries:[/cyan]")
            for d in mp.discoveries:
                console.print(f"  • {d.id}")
        
        console.print("\n[dim]Use --component <id> to see details[/dim]")


@main.command()
@click.argument("directory", type=click.Path(exists=True))
@click.option(
    "--recursive", "-r",
    is_flag=True,
    help="Search recursively in subdirectories"
)
def scan(directory: str, recursive: bool):
    """
    Scan a directory for management pack files.
    
    DIRECTORY: Path to scan for management packs
    """
    print_banner()
    
    dir_path = Path(directory)
    pattern = "**/*.xml" if recursive else "*.xml"
    
    mp_files = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for management packs...", total=None)
        
        for xml_file in dir_path.glob(pattern):
            if ManagementPackParser.is_management_pack(xml_file):
                mp_files.append(xml_file)
        
        progress.update(task, completed=True)
    
    if not mp_files:
        console.print("[yellow]No management pack files found.[/yellow]")
        return
    
    console.print(f"\n[green]Found {len(mp_files)} management pack(s):[/green]\n")
    
    table = Table()
    table.add_column("File", style="cyan")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Monitors", justify="right")
    table.add_column("Rules", justify="right")
    
    for mp_file in mp_files:
        try:
            parser = ManagementPackParser(mp_file)
            mp = parser.parse()
            table.add_row(
                mp_file.name,
                mp.metadata.display_name or mp.metadata.name,
                mp.metadata.version,
                str(len(mp.monitors)),
                str(len(mp.rules)),
            )
        except Exception as e:
            table.add_row(
                mp_file.name,
                f"[red]Error: {str(e)[:30]}[/red]",
                "-",
                "-",
                "-",
            )
    
    console.print(table)


def _format_text_report(report, verbose: bool) -> str:
    """Format the migration report as text."""
    lines = []
    
    lines.append("=" * 70)
    lines.append("SCOM to Azure Monitor Migration Analysis")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Management Pack: {report.management_pack.display_name or report.management_pack.name}")
    lines.append(f"Version: {report.management_pack.version}")
    lines.append(f"Analysis Date: {report.generated_at}")
    lines.append("")
    
    lines.append("-" * 70)
    lines.append("SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Total Components: {report.total_components}")
    lines.append(f"Easily Migratable: {report.migratable_components}")
    lines.append(f"Requires Manual Review: {report.requires_manual_review}")
    lines.append(f"Cannot Migrate: {report.cannot_migrate}")
    lines.append(f"Estimated Effort: {report.estimated_effort_hours} hours")
    lines.append("")
    
    lines.append("-" * 70)
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 70)
    for rec in report.overall_recommendations:
        lines.append(f"\n{rec}")
    lines.append("")
    
    lines.append("-" * 70)
    lines.append("PREREQUISITES")
    lines.append("-" * 70)
    for prereq in report.prerequisites:
        lines.append(f"• {prereq}")
    lines.append("")
    
    if verbose:
        lines.append("-" * 70)
        lines.append("DETAILED MAPPINGS")
        lines.append("-" * 70)
        for mapping in report.mappings:
            lines.append(f"\n[{mapping.source_type}] {mapping.source_name}")
            lines.append(f"  Complexity: {mapping.migration_complexity.value}")
            for rec in mapping.recommendations:
                lines.append(f"  → {rec.target_type.value}: {rec.description}")
            if mapping.limitations:
                lines.append("  Limitations:")
                for lim in mapping.limitations:
                    lines.append(f"    - {lim}")
    
    return "\n".join(lines)


def _display_monitor_details(monitor):
    """Display detailed monitor information."""
    console.print(Panel(
        f"[bold]{monitor.display_name or monitor.name}[/bold]",
        title="Monitor Details"
    ))
    
    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("ID", monitor.id)
    table.add_row("Type", monitor.monitor_type.value)
    table.add_row("Target Class", monitor.target_class)
    table.add_row("Enabled", "Yes" if monitor.enabled else "No")
    table.add_row("Generates Alert", "Yes" if monitor.generates_alert else "No")
    if monitor.generates_alert:
        table.add_row("Alert Severity", monitor.alert_severity.value)
    if monitor.threshold is not None:
        table.add_row("Threshold", str(monitor.threshold))
    if monitor.data_source:
        table.add_row("Data Source Type", monitor.data_source.data_source_type.value)
    
    console.print(table)
    
    # Show mapping
    mapper = AzureMonitorMapper()
    mapping = mapper.map_monitor(monitor)
    
    console.print("\n[bold]Azure Monitor Recommendations:[/bold]")
    for rec in mapping.recommendations:
        console.print(f"  • {rec.target_type.value}: {rec.description}")
        if rec.kql_query:
            console.print("\n[dim]Suggested KQL Query:[/dim]")
            console.print(Syntax(rec.kql_query, "sql", theme="monokai"))


def _display_rule_details(rule):
    """Display detailed rule information."""
    console.print(Panel(
        f"[bold]{rule.display_name or rule.name}[/bold]",
        title="Rule Details"
    ))
    
    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value")
    
    table.add_row("ID", rule.id)
    table.add_row("Type", rule.rule_type.value)
    table.add_row("Target Class", rule.target_class)
    table.add_row("Enabled", "Yes" if rule.enabled else "No")
    table.add_row("Generates Alert", "Yes" if rule.generates_alert else "No")
    if rule.data_source:
        table.add_row("Data Source Type", rule.data_source.data_source_type.value)
    
    console.print(table)


if __name__ == "__main__":
    main()
