"""Thin wrappers around the external binaries: subfinder, nuclei, subzy.

Each wrapper checks the binary is present (skipping gracefully with an install
hint if not), runs it with a timeout, and returns parsed results. Nothing here
knows about scope or batching — that orchestration lives in :mod:`pipeline`.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import List, Optional, Sequence

from .models import NucleiFinding, TakeoverFinding
from .util import dedupe, have_binary

log = logging.getLogger("superscope.tools")

INSTALL_HINTS = {
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subzy": "go install github.com/PentestPad/subzy@latest",
    "notify": "go install github.com/projectdiscovery/notify/cmd/notify@latest",
}


class ToolError(Exception):
    pass


def _write_tmp_list(items: Sequence[str], workdir: str, prefix: str) -> str:
    os.makedirs(workdir, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt", dir=workdir)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(items) + "\n")
    return path


def _run(cmd: List[str], timeout: int, stdin: Optional[str] = None
         ) -> subprocess.CompletedProcess:
    log.debug("exec: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


# --------------------------------------------------------------------- subfinder
def run_subfinder(config, roots: Sequence[str], workdir: str) -> List[str]:
    """Enumerate subdomains for every registrable domain in ``roots``."""
    binary = config.get("subfinder.binary", "subfinder")
    if not roots:
        return []
    if not have_binary(binary):
        log.warning("%s not installed — skipping subdomain enumeration (install: %s)",
                    binary, INSTALL_HINTS.get("subfinder", ""))
        return list(roots)  # fall back to the apex domains themselves

    roots_file = _write_tmp_list(list(dedupe(roots)), workdir, "roots_")
    cmd = [binary, "-dL", roots_file]
    pc = config.get("subfinder.provider_config")
    if pc:
        cmd += ["-pc", os.path.expanduser(pc)]
    cmd += list(config.get("subfinder.extra_args", []))

    timeout = int(config.get("subfinder.timeout_seconds", 900))
    try:
        proc = _run(cmd, timeout)
    except subprocess.TimeoutExpired:
        log.error("subfinder timed out after %ss", timeout)
        return list(roots)
    if proc.returncode != 0:
        log.warning("subfinder exited %d: %s", proc.returncode, proc.stderr.strip()[:400])

    subs = [l.strip().lower() for l in proc.stdout.splitlines() if l.strip()]
    # Always keep the apex domains in the scan set as well.
    return dedupe([*roots, *subs])


# ------------------------------------------------------------------------ nuclei
def run_nuclei(config, hosts: Sequence[str], templates_dir: str,
               workdir: str) -> List[NucleiFinding]:
    """Run Nuclei over ``hosts`` with every template under ``templates_dir``."""
    binary = config.get("nuclei.binary", "nuclei")
    hosts = list(dedupe(h for h in hosts if h))
    if not hosts:
        return []
    if not have_binary(binary):
        log.warning("%s not installed — skipping scan (install: %s)",
                    binary, INSTALL_HINTS.get("nuclei", ""))
        return []
    if not templates_dir or not os.path.isdir(templates_dir):
        log.error("Nuclei templates dir missing (%s); skipping scan", templates_dir)
        return []

    hosts_file = _write_tmp_list(hosts, workdir, "hosts_")
    cmd = [binary, "-l", hosts_file, "-t", templates_dir]
    severities = config.get("nuclei.severities", []) or []
    if severities:
        cmd += ["-severity", ",".join(severities)]
    rl = config.get("nuclei.rate_limit")
    if rl:
        cmd += ["-rl", str(rl)]
    conc = config.get("nuclei.concurrency")
    if conc:
        cmd += ["-c", str(conc)]
    cmd += list(config.get("nuclei.extra_args", []))

    timeout = int(config.get("nuclei.timeout_seconds", 3600))
    try:
        proc = _run(cmd, timeout)
    except subprocess.TimeoutExpired:
        log.error("nuclei timed out after %ss on a %d-host batch", timeout, len(hosts))
        return []
    if proc.returncode not in (0, 1):  # nuclei exits 0 with no findings, sometimes 1
        log.warning("nuclei exited %d: %s", proc.returncode, proc.stderr.strip()[:400])

    return _parse_nuclei(proc.stdout)


def _parse_nuclei(stdout: str) -> List[NucleiFinding]:
    findings: List[NucleiFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        findings.append(NucleiFinding(
            host=obj.get("host") or obj.get("url") or "",
            template_id=obj.get("template-id") or obj.get("templateID") or "",
            name=info.get("name", ""),
            severity=(info.get("severity") or "").lower(),
            matched_at=obj.get("matched-at") or obj.get("matched") or "",
            raw=obj,
        ))
    return findings


# ------------------------------------------------------------------------- subzy
def run_subzy(config, hosts: Sequence[str], workdir: str) -> List[TakeoverFinding]:
    """Check every host for subdomain takeover; return only VULNERABLE ones."""
    binary = config.get("subzy.binary", "subzy")
    hosts = list(dedupe(h for h in hosts if h))
    if not hosts:
        return []
    if not have_binary(binary):
        log.warning("%s not installed — skipping takeover checks (install: %s)",
                    binary, INSTALL_HINTS.get("subzy", ""))
        return []

    targets_file = _write_tmp_list(hosts, workdir, "subzy_")
    cmd = [binary, "run", "--targets", targets_file]
    cmd += list(config.get("subzy.extra_args", []))

    timeout = int(config.get("subzy.timeout_seconds", 1800))
    try:
        proc = _run(cmd, timeout)
    except subprocess.TimeoutExpired:
        log.error("subzy timed out after %ss", timeout)
        return []

    return _parse_subzy(proc.stdout)


def _parse_subzy(stdout: str) -> List[TakeoverFinding]:
    """Keep only lines subzy flags as VULNERABLE (never the NOT VULNERABLE ones)."""
    findings: List[TakeoverFinding] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        upper = line.upper()
        if "VULNERABLE" not in upper or "NOT VULNERABLE" in upper:
            continue
        host, service = _extract_subzy_fields(line)
        if host:
            findings.append(TakeoverFinding(host=host, service=service, raw=line))
    return findings


def _host_from_token(tok: str) -> str:
    """Reduce a token to a bare host, if it looks like one.

    Handles plain hosts (``sub.example.com``) and URLs
    (``https://sub.example.com/x`` -> ``sub.example.com``).
    """
    t = tok.strip().strip("[](){}<>,")
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split(":", 1)[0].lower()
    if "." in t and " " not in t and t.upper() != "NOT":
        return t
    return ""


def _extract_subzy_fields(line: str) -> tuple[str, str]:
    """Pull the host and (optional) fingerprinted service from a subzy line."""
    host = ""
    service = ""
    for tok in line.replace("[", " ").replace("]", " ").split():
        if "vulnerable" in tok.lower():
            continue
        cand = _host_from_token(tok)
        if cand and not host:
            host = cand
    low = line.lower()
    if "engine:" in low:
        service = line.split("engine:", 1)[1].strip().split()[0].strip("[]")
    return host, service
