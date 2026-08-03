"""
Security Scanning Pipeline Orchestrator
-----------------------------------------
Clones a target repository, runs Semgrep, Gitleaks, and OWASP Dependency-Check
against it, and saves each tool's raw output plus a normalized finding set.
 
Usage:
    python scan_pipeline.py https://github.com/org/repo.git
    python scan_pipeline.py https://github.com/org/repo.git --branch main
    python scan_pipeline.py /path/to/local/repo --local
 
Requirements (must be installed and on PATH):
    - git
    - semgrep            (pip install semgrep)
    - gitleaks           (https://github.com/gitleaks/gitleaks)
    - dependency-check.sh / dependency-check.bat
      (https://owasp.org/www-project-dependency-check/)
"""
import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import tempfile
import time

from Scanners import run_dependency_check, run_gitleaks, run_semgrep, run_trivy
from findingstruct import Finding
from normalizarion import SEVERITY_ORDER, correlate_and_prioritize
from scanrepo import get_repo 

def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
 
 
OUTPUT_ROOT = Path("scan_results")
 
def main():
    parser = argparse.ArgumentParser(description="Security scanning pipeline orchestrator")
    parser.add_argument("source", help="Git URL to clone, or local path if --local is set")
    parser.add_argument("--branch", default=None, help="Branch to clone (default: repo default)")
    parser.add_argument("--local", action="store_true", help="Treat SOURCE as a local repo path")
    parser.add_argument("--keep-clone", action="store_true",
                         help="Don't delete the cloned repo after scanning")
    args = parser.parse_args()
 
    run_id = timestamp()
    out_dir = OUTPUT_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
 
    tmp_dir = Path(tempfile.mkdtemp(prefix="scan_pipeline_"))
    start = time.time()
 
    try:
        repo_path = get_repo(args.source, args.local, args.branch, tmp_dir)
 
        all_findings: list[Finding] = []
        # all_findings += run_semgrep(repo_path, out_dir)
        all_findings += run_gitleaks(repo_path, out_dir)
        all_findings += run_dependency_check(repo_path, out_dir)
        all_findings += run_trivy(repo_path,out_dir)
 
        prioritized = correlate_and_prioritize(all_findings)
 
        summary = {
            "run_id": run_id,
            "source": args.source,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.time() - start, 2),
            "total_findings": len(prioritized),
            "by_severity": {
                sev: sum(1 for f in prioritized if f.severity == sev)
                for sev in SEVERITY_ORDER
            },
            "findings": [asdict(f) for f in prioritized],
        }
 
        normalized_path = out_dir / "normalized_findings.json"
        normalized_path.write_text(json.dumps(summary, indent=2))
 
        print("\n=== Scan complete ===")
        print(f"Total findings: {summary['total_findings']}")
        for sev, count in summary["by_severity"].items():
            if count:
                print(f"  {sev:>8}: {count}")
        print(f"\nResults saved to: {out_dir.resolve()}")
        print(f"  - {normalized_path.name}  (normalized, correlated, prioritized)")
        print("  - semgrep_raw.json / gitleaks_raw.json / dependency_check_raw.json (raw tool output)")
 
    finally:
        if not (args.local or args.keep_clone):
            shutil.rmtree(tmp_dir, ignore_errors=True)
 
 
if __name__ == "__main__":
    main()
 