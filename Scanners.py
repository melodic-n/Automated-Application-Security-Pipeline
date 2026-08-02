import json
import shutil
import subprocess
from pathlib import Path

from findingstruct import Finding


 
def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command, returning (exit_code, stdout, stderr). Never raises on non-zero exit,
    since these scanners exit non-zero when findings are present."""
    print(f"  $ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr
 
 
def check_tool_available(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_semgrep(repo_path: Path, out_dir: Path) -> list[Finding]:
    print("[*] Running Semgrep ...")
    if not check_tool_available("semgrep"):
        print("  ! semgrep not found on PATH, skipping")
        return []
 
    raw_path = out_dir / "semgrep_raw.json"
    code, out, err = run_cmd(
        ["semgrep", "--config=auto", "--json", "--quiet", str(repo_path)]
    )
    raw_path.write_text(out or "{}")
 
    findings = []
    try:
        data = json.loads(out or "{}")
        for i, r in enumerate(data.get("results", [])):
            sev = r.get("extra", {}).get("severity", "info").lower()
            sev_map = {"error": "high", "warning": "medium", "info": "low"}
            findings.append(Finding(
                id=f"semgrep-{i}",
                tool="semgrep",
                category="sast",
                severity=sev_map.get(sev, "info"),
                title=r.get("check_id", "unknown-rule"),
                description=r.get("extra", {}).get("message", ""),
                file=r.get("path", ""),
                line=r.get("start", {}).get("line"),
                raw=r,
            ))
    except json.JSONDecodeError:
        print("  ! could not parse semgrep output")
 
    print(f"  -> {len(findings)} findings ({raw_path.name})")
    return findings
 
 
def run_gitleaks(repo_path: Path, out_dir: Path) -> list[Finding]:
    print("[*] Running Gitleaks ...")
    if not check_tool_available("gitleaks"):
        print("  ! gitleaks not found on PATH, skipping")
        return []
 
    raw_path = out_dir / "gitleaks_raw.json"
    run_cmd([
        "gitleaks", "detect",
        "--source", str(repo_path),
        "--report-format", "json",
        "--report-path", str(raw_path),
        "--no-git",  # scan working tree; drop this flag if you want full git history scanned
        "--exit-code", "0",
    ])
 
    findings = []
    if raw_path.exists() and raw_path.stat().st_size > 0:
        try:
            data = json.loads(raw_path.read_text())
            for i, r in enumerate(data or []):
                findings.append(Finding(
                    id=f"gitleaks-{i}",
                    tool="gitleaks",
                    category="secret",
                    severity="critical",
                    title=r.get("RuleID", "secret-detected"),
                    description=r.get("Description", ""),
                    file=r.get("File", ""),
                    line=r.get("StartLine"),
                    raw=r,
                ))
        except json.JSONDecodeError:
            print("  ! could not parse gitleaks output")
 
    print(f"  -> {len(findings)} findings ({raw_path.name})")
    return findings
 
 
def run_dependency_check(repo_path: Path, out_dir: Path) -> list[Finding]:
    print("[*] Running Dependency-Check ...")
    dc_bin = "dependency-check.sh" if shutil.which("dependency-check.sh") else "dependency-check"
    if not check_tool_available(dc_bin):
        print("  ! dependency-check not found on PATH, skipping")
        return []
 
    raw_path = out_dir / "dependency_check_raw.json"
    run_cmd([
        dc_bin,
        "--project", repo_path.name,
        "--scan", str(repo_path),
        "--format", "JSON",
        "--out", str(out_dir),
        "--noupdate",  # drop this once you want the CVE DB refreshed each run
    ])
 
    # dependency-check writes dependency-check-report.json into --out
    produced = out_dir / "dependency-check-report.json"
    findings = []
    if produced.exists():
        produced.rename(raw_path)
        try:
            data = json.loads(raw_path.read_text())
            sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            for dep in data.get("dependencies", []):
                for i, vuln in enumerate(dep.get("vulnerabilities", []) or []):
                    findings.append(Finding(
                        id=f"depcheck-{dep.get('fileName','?')}-{i}",
                        tool="dependency-check",
                        category="dependency",
                        severity=sev_map.get(vuln.get("severity", "").upper(), "info"),
                        title=vuln.get("name", "vulnerable-dependency"),
                        description=vuln.get("description", ""),
                        file=dep.get("filePath", dep.get("fileName", "")),
                        line=None,
                        raw=vuln,
                    ))
        except json.JSONDecodeError:
            print("  ! could not parse dependency-check output")
 
    print(f"  -> {len(findings)} findings ({raw_path.name})")
    return findings
 