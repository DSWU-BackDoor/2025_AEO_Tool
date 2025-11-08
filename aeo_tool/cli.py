# aeo_tool/cli.py
import subprocess
import click
from rich.console import Console
from aeo_tool.sbom.sbom import SBOMGenerator
from aeo_tool.map import map_sbom_vulns

console = Console()

@click.group(help="AEO Tool CLI")
def cli():
    pass

@cli.command(help="Generate SBOM via Syft")
@click.option("--path", "target_path", required=True, help="Target path (e.g., . / dir:/x / docker:image)")
@click.option("--output", "output_path", required=True, help="Output file (CycloneDX JSON)")
@click.option("--format", "fmt",
              type=click.Choice(["cyclonedx","spdx","json"], case_sensitive=False),
              default="cyclonedx", show_default=True)
@click.option("--exclude", "excludes", multiple=True,
              help="Glob to exclude (repeatable). e.g. --exclude '**/.venv/**'")
def sbom(target_path, output_path, fmt, excludes):
    gen = SBOMGenerator()
    try:
        # call with excludes (SBOMGenerator now supports it)
        out = gen.generate_from_path(target_path, output_path, format=fmt, excludes=excludes or None)
        console.print(f"✅ SBOM saved to [bold]{out}[/]")
    except Exception as e:
        console.print(f"[red]SBOM generation failed:[/] {e}")
        raise SystemExit(1)

@cli.command(help="Run grype scan on SBOM (output JSON)")
@click.option("--sbom", "sbom_path", required=True, help="CycloneDX SBOM file")
@click.option("--output", "out_path", default="out/vulns.json", help="grype JSON output")
def scan(sbom_path, out_path):
    cmd = ["grype", f"sbom:{sbom_path}", "-o", "json"]
    console.print(f"▶ Running: {' '.join(cmd)}")
    with open(out_path, "w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE, text=True)
    if proc.returncode not in (0,):
        console.print("[yellow]grype finished with nonzero exit code; check stderr[/]")
        console.print(proc.stderr)
    console.print(f"✅ vuln JSON: {out_path}")

@cli.command(name="map", help="Map vulnerabilities (grype) to SBOM components")
@click.option("--sbom", "sbom_path", default="out/sbom-cyclonedx.json")
@click.option("--vuln", "vuln_path", default="out/vulns.json")
@click.option("--out", "out_csv", default="out/mapping.csv")
def map_cmd(sbom_path, vuln_path, out_csv):
    console.print(f"▶ Mapping SBOM ({sbom_path}) -> Vulns ({vuln_path}) -> {out_csv}")
    try:
        map_sbom_vulns(sbom_path, vuln_path, out_csv)
        console.print(f"✅ Mapping output (csv): {out_csv}")
    except Exception as e:
        console.print(f"[red]Mapping failed:[/] {e}")
        raise SystemExit(1)

if __name__ == "__main__":
    cli()
