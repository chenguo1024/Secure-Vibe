"""fetch_datasets.py — 一键获取外部数据集（需要网络时运行）.

三项外部依赖的统一入口（当前环境网络不可达，脚本已就绪）:

  1. SecurityEval（GitHub，论文级评测集）
     python tools/fetch_datasets.py --securityeval --dir D:/datasets/SecurityEval

  2. GHSA-CySec（ModelScope 国内可达，需先在网页申请）
     python tools/fetch_datasets.py --ghsa --dir D:/datasets/GHSA-CySec

  3. 任意 HF 数据集（可用 HF_ENDPOINT=https://hf-mirror.com 走镜像）
     python tools/fetch_datasets.py --hf s2labres/security-eval --dir D:/datasets/security-eval

也可一次性全部:  python tools/fetch_datasets.py --all --dir D:/datasets
获取后:  SecurityEval → tools/run_evaluation.py --path <dir>
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
    """SecurityEval 主仓库（含 Id_<CWE>/ParetoProperties 样本）。"""
    dst.mkdir(parents=True, exist_ok=True)
    print("[1/3] 克隆 SecurityEval（GitHub，国内需代理）")
    return _shell(["git", "clone", "--depth", "1",
                   "https://github.com/s2labres/security-eval.git", str(dst)])


def fetch_ghsa(dst: Path) -> int:
    """GHSA-CySec（ModelScope 国内可达，需先申请下载权限）。"""
    dst.mkdir(parents=True, exist_ok=True)
    print("[2/3] 下载 GHSA-CySec（ModelScope）")
    print("  前置: 浏览器打开 https://www.modelscope.cn/datasets/couvor/GHSA-CySec 申请访问")
    return _shell(["modelscope", "download", "--dataset", "couvor/GHSA-CySec",
                   "--local_dir", str(dst)])


def fetch_hf(repo: str, dst: Path) -> int:
    """任意 HuggingFace 数据集（可用镜像）。"""
    dst.mkdir(parents=True, exist_ok=True)
    print(f"[3/3] 下载 HF 数据集 {repo}")
    code = (
        "from datasets import load_dataset\n"
        f"ds = load_dataset('{repo}')\n"
        f"ds.save_to_disk(r'{dst}')\n"
        "print('saved to', r'%s')\n" % dst
    )
    return _shell([sys.executable, "-c", code])


def main() -> int:
    ap = argparse.ArgumentParser(description="一键获取 Secure-Vibe 外部数据集")
    ap.add_argument("--securityeval", action="store_true", help="获取 SecurityEval")
    ap.add_argument("--ghsa", action="store_true", help="获取 GHSA-CySec")
    ap.add_argument("--hf", default="", help="通过 HF 镜像获取任意数据集（repo id）")
    ap.add_argument("--all", action="store_true", help="全部获取")
    ap.add_argument("--dir", default=".", help="目标目录")
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
        print("\n部分获取失败：当前环境需可用网络（GitHub 需代理）。", file=sys.stderr)
    else:
        print("\n获取完成。用法见文件头注释。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
