"""fetch_datasets.py — One-shot fetch of external datasets (run only when needed).

  - the unified entry point for external data (the current network cannot reach them; script is ready):

    1. SecurityEval (GitHub, malicious-code-generation dataset)
     python tools/fetch_datasets.py --securityeval --dir D:/datasets/SecurityEval

    2. GHSA-CySec (ModelScope, currently reachable; compute resources need an application)
     python tools/fetch_datasets.py --ghsa --dir D:/datasets/GHSA-CySec

    3. other HF datasets (can set HF_ENDPOINT=https://hf-mirror.com to go through a mirror)
     python tools/fetch_datasets.py --hf s2labres/security-eval --dir D:/datasets/security-eval

  - one-shot download:  python tools/fetch_datasets.py --all --dir D:/datasets
Afterwards:  SecurityEval -> tools/run_evaluation.py --path <dir>
          GHSA-CySec → tools/mine_cwe_rules.py <dir>
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def _shell(cmd: list[str]) -> int:
    print("  $ " + " ".join(cmd))
    return subprocess.call(cmd)


def fetch_securityeval(dst: Path) -> int:
    """The standalone SecurityEval repo (contains the Id_<CWE>/Pareto Properties structure)."""
    dst.mkdir(parents=True, exist_ok=True)
    print("[1/3] clone SecurityEval (GitHub, may need a proxy)")
    return _shell(["git", "clone", "--depth", "1",
                   "https://github.com/s2labres/security-eval.git", str(dst)])


def fetch_ghsa(dst: Path) -> int:
    """GHSA-CySec: reachable via ModelScope; access permission may be needed."""
    dst.mkdir(parents=True, exist_ok=True)
    print("[2/3] download GHSA-CySec (ModelScope)")
    print("  prerequisite: apply for access at https://www.modelscope.cn/datasets/couvor/GHSA-CySec")
    return _shell(["modelscope", "download", "--dataset", "couvor/GHSA-CySec",
                   "--local_dir", str(dst)])


def fetch_hf(repo: str, dst: Path) -> int:
    """Other HuggingFace datasets (optional, mirror-supported)."""
    dst.mkdir(parents=True, exist_ok=True)
    print(f"[3/3] download HF dataset {repo}")
    code = (
        "from datasets import load_dataset\n"
        f"ds = load_dataset('{repo}')\n"
        f"ds.save_to_disk(r'{dst}')\n"
        "print('saved to', r'%s')\n" % dst
    )
    return _shell([sys.executable, "-c", code])


def main() -> int:
    ap = argparse.ArgumentParser(description="one-shot fetcher for Secure-Vibe external datasets")
    ap.add_argument("--securityeval", action="store_true", help="fetch SecurityEval")
    ap.add_argument("--ghsa", action="store_true", help="fetch GHSA-CySec")
    ap.add_argument("--hf", default="", help="fetch another dataset via HF (repo id)")
    ap.add_argument("--all", action="store_true", help="fetch everything")
    ap.add_argument("--dir", default=".", help="target directory")
    args = ap.parse_args()

    base = Path(args.dir); base.mkdir(parents=True, exist_ok=True)
    rc = 0
    if args.securityeval or args.all:
        rc |= fetch_securityeval(base / "SecurityEval")
    if args.ghsa or args.all:
        rc |= fetch_ghsa(base / "GHSA-CySec")
    if args.hf:
        rc |= fetch_hf(args.hf, base / args.hf.replace("/", "__"))
    if rc:
        print("\npartial failures: the current network cannot reach some sources (GitHub needs a proxy)", file=sys.stderr)
    else:
        print("\ndone. Usage is in the file header.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
