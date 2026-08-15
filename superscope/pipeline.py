"""The orchestrator that runs the whole flow.

    scope
      ├─ wildcard entries ─ subfinder ─ (blocks of N) ─ nuclei ─ notify:findings
      ├─ plain entries    ───────────── (blocks of N) ─ nuclei ─ notify:findings
      └─ every host found ───────────────────────────── subzy  ─ notify:takeover
"""
from __future__ import annotations

import logging
import os
from typing import List

from . import notify, scope as scope_mod, templates as tmpl_mod, tools
from .models import RunStats, TakeoverFinding
from .util import batched, dedupe

log = logging.getLogger("superscope.pipeline")


def run(config) -> RunStats:
    workdir = os.path.abspath(os.path.expanduser(config.get("flow.workdir", "./output")))
    os.makedirs(workdir, exist_ok=True)
    batch_size = int(config.get("flow.batch_size", 30))
    stats = RunStats()

    # 1) Scope ---------------------------------------------------------------
    entries = scope_mod.load_scope(config, workdir)
    wildcard_entries, plain_entries = scope_mod.split_entries(entries)
    stats.wildcard_entries = len(wildcard_entries)
    stats.plain_entries = len(plain_entries)
    roots = scope_mod.wildcard_roots(wildcard_entries)
    plain_hosts = scope_mod.plain_hosts(plain_entries)

    if not entries:
        log.error("No in-scope targets resolved — nothing to do.")
        return stats

    # 2) Templates -----------------------------------------------------------
    templates_dir = None
    if config.get("flow.run_nuclei", True):
        templates_dir = tmpl_mod.resolve_templates_dir(config, workdir)

    # Dry run: show the plan and stop before touching any target.
    if config.get("flow.dry_run", False):
        _print_plan(roots, plain_hosts, batch_size, templates_dir)
        return stats

    all_hosts: List[str] = []  # everything subzy will later check

    # 3) Wildcard flow: subfinder -> nuclei in blocks -> notify --------------
    if wildcard_entries:
        if config.get("flow.run_subfinder", True):
            log.info("Enumerating subdomains for %d wildcard root(s)…", len(roots))
            subdomains = tools.run_subfinder(config, roots, workdir)
        else:
            subdomains = list(roots)
        subdomains = dedupe(subdomains)
        stats.subdomains_found = len(subdomains)
        all_hosts.extend(subdomains)
        log.info("%d host(s) from wildcard enumeration", len(subdomains))

        if config.get("flow.run_nuclei", True):
            _scan_in_blocks(config, subdomains, templates_dir, workdir,
                            batch_size, "wildcard", stats)

    # 4) Non-wildcard flow: nuclei -> notify --------------------------------
    if plain_hosts:
        all_hosts.extend(plain_hosts)
        if config.get("flow.run_nuclei", True):
            _scan_in_blocks(config, plain_hosts, templates_dir, workdir,
                            batch_size, "non-wildcard", stats)

    # 5) Takeover sweep over every located host -> notify (2nd webhook) ------
    all_hosts = dedupe(all_hosts)
    if config.get("flow.run_subzy", True) and all_hosts:
        log.info("Running subzy over %d host(s)…", len(all_hosts))
        takeovers: List[TakeoverFinding] = tools.run_subzy(config, all_hosts, workdir)
        stats.takeover_findings = len(takeovers)
        if takeovers:
            log.warning("%d VULNERABLE takeover(s) found", len(takeovers))
            notify.notify_takeovers(config, takeovers)
        else:
            log.info("No takeovers found — nothing sent to the takeover channel.")

    stats.hosts_scanned = len(all_hosts)
    _log_summary(stats)
    return stats


def _scan_in_blocks(config, hosts, templates_dir, workdir, batch_size,
                    label: str, stats: RunStats) -> None:
    """Nuclei-scan ``hosts`` in blocks, notifying per block on findings."""
    if not templates_dir:
        log.warning("No templates dir; skipping %s Nuclei scan", label)
        return
    hosts = dedupe(hosts)
    blocks = list(batched(hosts, batch_size))
    log.info("Scanning %d %s host(s) in %d block(s) of %d",
             len(hosts), label, len(blocks), batch_size)
    for i, block in enumerate(blocks, start=1):
        context = f"{label} block {i}/{len(blocks)}"
        log.info("Nuclei — %s (%d hosts)", context, len(block))
        findings = tools.run_nuclei(config, block, templates_dir, workdir)
        if findings:
            stats.nuclei_findings += len(findings)
            log.warning("%d finding(s) in %s", len(findings), context)
            notify.notify_findings(config, findings, context=context)


def _print_plan(roots, plain_hosts, batch_size, templates_dir) -> None:
    print("=== superscope dry run ===")
    print(f"wildcard roots (subfinder): {len(roots)}")
    for r in roots[:20]:
        print(f"  * {r}")
    if len(roots) > 20:
        print(f"  … (+{len(roots) - 20} more)")
    print(f"non-wildcard hosts (direct nuclei): {len(plain_hosts)}")
    for h in plain_hosts[:20]:
        print(f"  - {h}")
    if len(plain_hosts) > 20:
        print(f"  … (+{len(plain_hosts) - 20} more)")
    print(f"nuclei block size: {batch_size}")
    print(f"templates dir: {templates_dir or '(not resolved)'}")
    print("No scans launched (flow.dry_run = true).")


def _log_summary(stats: RunStats) -> None:
    log.info("──────── summary ────────")
    log.info("wildcard entries : %d", stats.wildcard_entries)
    log.info("plain entries    : %d", stats.plain_entries)
    log.info("subdomains found : %d", stats.subdomains_found)
    log.info("hosts scanned    : %d", stats.hosts_scanned)
    log.info("nuclei findings  : %d", stats.nuclei_findings)
    log.info("takeovers        : %d", stats.takeover_findings)
