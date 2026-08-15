"""Fetch and parse the rix4uni/scope data.

The upstream layout (https://github.com/rix4uni/scope) stores one entry per
line under ``data/<Platform>/<platform>_inscope.txt`` and
``..._outofscope.txt``. Entries mix concrete hosts (``api.example.com``) and
wildcards (``*.example.com``, ``*-prod.example.com``, ``portal.*.example.com``).

This module clones (or reads a local checkout of) that repo, keeps only the
in-scope entries for the configured platforms, drops anything that also appears
out-of-scope, and classifies each survivor as wildcard or plain. For wildcards
it derives the registrable domain (``example.com``) that subfinder will
enumerate.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, List, Set, Tuple

from .models import ScopeEntry
from .util import ensure_repo, registrable_domain

log = logging.getLogger("superscope.scope")

PLATFORM_DIR = {"bugcrowd": "Bugcrowd", "hackerone": "Hackerone"}


def _read_lines(path: str) -> List[str]:
    if not os.path.isfile(path):
        return []
    out: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            out.append(entry.lower())
    return out


def _scope_files(root: str, platform: str) -> Tuple[str, str]:
    folder = PLATFORM_DIR[platform]
    base = os.path.join(root, "data", folder)
    return (
        os.path.join(base, f"{platform}_inscope.txt"),
        os.path.join(base, f"{platform}_outofscope.txt"),
    )


def resolve_scope_path(config, workdir: str) -> str:
    """Return a local path to the scope checkout, cloning if necessary."""
    local = config.get("scope.local_path")
    if local:
        local = os.path.expanduser(local)
        if not os.path.isdir(local):
            raise FileNotFoundError(f"scope.local_path does not exist: {local}")
        return local
    dest = os.path.join(workdir, "scope")
    ensure_repo(config.get("scope.repo"), dest, update=True)
    return dest


def load_scope(config, workdir: str) -> List[ScopeEntry]:
    """Load, filter and classify in-scope entries for the configured platforms."""
    root = resolve_scope_path(config, workdir)
    platforms = [p.lower() for p in config.get("scope.platforms", ["bugcrowd", "hackerone"])]
    respect_oos = bool(config.get("scope.respect_outofscope", True))
    include_roots = {r.lower() for r in config.get("scope.include_roots", []) or []}
    exclude_roots = {r.lower() for r in config.get("scope.exclude_roots", []) or []}

    entries: Dict[str, ScopeEntry] = {}
    for platform in platforms:
        if platform not in PLATFORM_DIR:
            log.warning("Unknown platform %r — skipping", platform)
            continue
        inscope_file, oos_file = _scope_files(root, platform)
        inscope = _read_lines(inscope_file)
        oos: Set[str] = set(_read_lines(oos_file)) if respect_oos else set()
        if not inscope:
            log.warning("No in-scope entries read for %s (looked in %s)",
                        platform, inscope_file)

        for raw in inscope:
            if raw in oos:
                continue
            root_domain = registrable_domain(raw)
            if not root_domain:
                continue
            if include_roots and root_domain not in include_roots:
                continue
            if root_domain in exclude_roots:
                continue
            entry = ScopeEntry(
                raw=raw,
                platform=platform,
                is_wildcard="*" in raw,
                root=root_domain,
            )
            entries.setdefault(entry.key, entry)

    result = list(entries.values())
    log.info("Loaded %d in-scope entries (%d wildcard, %d plain) across %s",
             len(result),
             sum(1 for e in result if e.is_wildcard),
             sum(1 for e in result if not e.is_wildcard),
             ", ".join(platforms))
    return result


def split_entries(entries: List[ScopeEntry]) -> Tuple[List[ScopeEntry], List[ScopeEntry]]:
    """Return ``(wildcard_entries, plain_entries)``."""
    wildcard = [e for e in entries if e.is_wildcard]
    plain = [e for e in entries if not e.is_wildcard]
    return wildcard, plain


def wildcard_roots(entries: List[ScopeEntry]) -> List[str]:
    """Deduplicated registrable domains to feed subfinder."""
    seen: Set[str] = set()
    roots: List[str] = []
    for e in entries:
        if e.is_wildcard and e.root and e.root not in seen:
            seen.add(e.root)
            roots.append(e.root)
    return roots


def plain_hosts(entries: List[ScopeEntry]) -> List[str]:
    """Concrete hosts from non-wildcard entries, ready for direct scanning."""
    seen: Set[str] = set()
    hosts: List[str] = []
    for e in entries:
        if not e.is_wildcard and e.raw not in seen:
            seen.add(e.raw)
            hosts.append(e.raw)
    return hosts
