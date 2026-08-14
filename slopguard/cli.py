import json
import sys
import subprocess
import click
from pathlib import Path
from typing import List
from slopguard.config import load_config
from slopguard.detection.engine import DetectionEngine
from slopguard.interceptor.shell_hook import Interceptor, is_non_interactive
from slopguard.intel.feed_sync import sync_intel_feed


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """SlopGuard: Defence against slopsquatting AI agent package hallucinations."""
    pass


@cli.command("check")
@click.argument("package_name")
@click.option("--ecosystem", "-e", default="npm", type=click.Choice(["npm", "pypi"], case_sensitive=False), help="Target ecosystem (npm or pypi)")
@click.option("--json-output", "--json", is_flag=True, help="Output JSON format")
def check_cmd(package_name: str, ecosystem: str, json_output: bool):
    """Perform a manual risk check on a package name."""
    config = load_config()
    engine = DetectionEngine()
    result = engine.analyze_package(package_name, ecosystem, config)

    if json_output:
        click.echo(json.dumps(result.model_dump(), indent=2))
        return

    click.echo(f"\n🔍 SlopGuard Check: {package_name} ({ecosystem.upper()})")
    click.echo(f"Risk Score: {result.risk_score:.1f} / 100.0")
    click.echo(f"Status: {'⚠️ SUSPICIOUS' if result.is_suspicious else '✅ LOW RISK'}\n")

    if result.signals:
        click.echo("Triggered Signals:")
        for sig in result.signals:
            click.echo(f"  • [{sig.severity}] {sig.name} (Score impact: +{sig.score_impact:.1f})")
            click.echo(f"    {sig.description}")
    else:
        click.echo("No risk signals detected.")


@cli.command("install")
@click.argument("args", nargs=-1, type=click.UNPROCESSED)
@click.option("--ecosystem", "-e", default="npm", type=click.Choice(["npm", "pypi"], case_sensitive=False), help="Target ecosystem")
def install_cmd(args, ecosystem: str):
    """Wrapper that checks packages with SlopGuard before running real pip/npm install."""
    if not args:
        click.echo("Error: Please provide package name(s) or command arguments.", err=True)
        sys.exit(1)

    cmd_str = f"{'pip' if ecosystem == 'pypi' else 'npm'} install " + " ".join(args)
    interceptor = Interceptor()
    allowed, results, explanation = interceptor.evaluate_command(cmd_str)

    click.echo(explanation)

    if not allowed:
        if is_non_interactive():
            click.echo("\n[SlopGuard] Installation aborted in CI / non-interactive environment.", err=True)
            sys.exit(1)
        
        # Interactive prompt
        if not click.confirm("\nDo you still wish to proceed with installation?", default=False):
            click.echo("Installation cancelled.")
            sys.exit(1)

    # Run real install command
    real_cmd = ["pip" if ecosystem == "pypi" else "npm", "install"] + list(args)
    click.echo(f"\nRunning: {' '.join(real_cmd)}...")
    res = subprocess.run(real_cmd)
    sys.exit(res.returncode)


@cli.command("scan-lockfile")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--json-output", "--json", is_flag=True, help="Output JSON format")
def scan_lockfile_cmd(file_path: str, json_output: bool):
    """Scan a package.json or requirements.txt file for high-risk packages."""
    path = Path(file_path)
    packages: List[str] = []
    ecosystem = "npm"

    if path.name == "requirements.txt" or path.suffix == ".txt":
        ecosystem = "pypi"
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0].strip()
                    if pkg:
                        packages.append(pkg)
    elif path.name == "package.json":
        ecosystem = "npm"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            packages.extend(list(deps.keys()) + list(dev_deps.keys()))

    if not packages:
        click.echo("No packages found in target file.")
        return

    config = load_config()
    engine = DetectionEngine()
    scanned_results = []
    suspicious_count = 0

    for pkg in packages:
        res = engine.analyze_package(pkg, ecosystem, config)
        scanned_results.append(res)
        if res.is_suspicious:
            suspicious_count += 1

    if json_output:
        click.echo(json.dumps([r.model_dump() for r in scanned_results], indent=2))
        return

    click.echo(f"🛡️ Scanned {len(packages)} packages in {path.name} ({ecosystem.upper()})")
    click.echo(f"Suspicious Packages Found: {suspicious_count}\n")

    for res in scanned_results:
        if res.is_suspicious:
            click.echo(f"⚠️ {res.package_name}: Risk Score {res.risk_score:.1f}")
            for sig in res.signals:
                click.echo(f"   - [{sig.severity}] {sig.description}")


@cli.command("update-intel")
def update_intel_cmd():
    """Manually trigger a threat feed refresh."""
    config = load_config()
    success = sync_intel_feed(config, force=True)
    if success:
        click.echo("✅ Threat intel feed updated successfully.")
    else:
        click.echo("⚠️ Threat intel feed update failed. Running in degraded offline mode.", err=True)


if __name__ == "__main__":
    cli()
