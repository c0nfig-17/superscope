"""Command-line interface for superscope."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .config import load_config
from .logging_setup import setup_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="superscope",
        description="Bugcrowd/HackerOne scope-driven scanning pipeline "
                    "(subfinder → nuclei → subzy → notify).",
    )
    p.add_argument("--config", help="Path to config.yaml (default: ./config.yaml "
                                    "or $SUPERSCOPE_CONFIG).")
    p.add_argument("--platforms", help="Comma-separated platforms to scan "
                                       "(overrides config; e.g. bugcrowd,hackerone).")
    p.add_argument("--workdir", help="Working directory for checkouts and output.")
    p.add_argument("--batch-size", type=int, help="Nuclei block size (default 30).")

    stage = p.add_argument_group("stage toggles")
    stage.add_argument("--no-subfinder", action="store_true",
                       help="Skip subdomain enumeration (scan apex domains only).")
    stage.add_argument("--no-nuclei", action="store_true", help="Skip Nuclei scanning.")
    stage.add_argument("--no-subzy", action="store_true", help="Skip takeover checks.")
    stage.add_argument("--no-notify", action="store_true",
                       help="Run everything but do not send Notify messages.")
    stage.add_argument("--dry-run", action="store_true",
                       help="Resolve scope and print the plan; launch nothing.")

    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging.")
    p.add_argument("-q", "--quiet", action="store_true", help="Warnings and errors only.")
    p.add_argument("--version", action="version",
                   version=f"superscope {__version__}")
    return p


def _apply_overrides(config, args) -> None:
    if args.platforms:
        config.data.setdefault("scope", {})["platforms"] = [
            x.strip().lower() for x in args.platforms.split(",") if x.strip()
        ]
    if args.workdir:
        config.data.setdefault("flow", {})["workdir"] = args.workdir
    if args.batch_size is not None:
        config.data.setdefault("flow", {})["batch_size"] = args.batch_size
    flow = config.data.setdefault("flow", {})
    if args.no_subfinder:
        flow["run_subfinder"] = False
    if args.no_nuclei:
        flow["run_nuclei"] = False
    if args.no_subzy:
        flow["run_subzy"] = False
    if args.dry_run:
        flow["dry_run"] = True
    if args.no_notify:
        config.data.setdefault("notify", {})["enabled"] = False


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(verbose=args.verbose, quiet=args.quiet)

    try:
        config = load_config(args.config)
    except (ValueError, RuntimeError, FileNotFoundError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    _apply_overrides(config, args)

    # Imported here so --help / config errors don't pay the import cost.
    from .pipeline import run

    try:
        stats = run(config)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Exit non-zero-free: findings are a normal outcome, not a failure.
    return 0 if not stats.errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
