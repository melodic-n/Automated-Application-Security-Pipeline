import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path


def run_cmd(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command, returning (exit_code, stdout, stderr). Never raises on non-zero exit,
    since these scanners exit non-zero when findings are present."""
    print(f"  $ {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr
 

def get_repo(source: str, is_local: bool, branch: str | None, workdir: Path)-> Path:
    if is_local:
        repo_path = Path(source).resolve()
        if not repo_path.exists():
            sys.exit(f"Local path does not exist: {repo_path}")
        print(f"[*] Using local repository at {repo_path}")
        return repo_path
 
    repo_path = workdir / "repo"
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [source, str(repo_path)]
 
    print(f"[*] Cloning {source} ...")
    code, out, err = run_cmd(cmd)
    if code != 0:
        sys.exit(f"git clone failed:\n{err}")
    print(f"[+] Cloned to {repo_path}")
    return repo_path
 
 