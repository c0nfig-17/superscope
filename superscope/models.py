"""Core data types shared across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class ScopeEntry:
    """A single line from a scope file.

    ``raw`` is the verbatim line (e.g. ``*.example.com`` or
    ``api.example.com``). ``is_wildcard`` is True when the entry contains a
    ``*`` and therefore describes a family of hosts to enumerate rather than a
    single concrete host. ``root`` is the registrable domain we hand to
    subfinder for wildcard entries (``example.com``).
    """

    raw: str
    platform: str  # "bugcrowd" | "hackerone"
    is_wildcard: bool
    root: str

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.raw}"


@dataclass
class NucleiFinding:
    """One Nuclei result, decoded from its JSONL output."""

    host: str
    template_id: str
    name: str
    severity: str
    matched_at: str
    raw: dict = field(default_factory=dict)

    def as_line(self) -> str:
        sev = (self.severity or "unknown").upper()
        name = self.name or self.template_id
        loc = self.matched_at or self.host
        return f"[{sev}] {self.template_id} — {name} @ {loc}"


@dataclass
class TakeoverFinding:
    """One vulnerable result from subzy."""

    host: str
    service: str
    raw: str = ""

    def as_line(self) -> str:
        svc = f" ({self.service})" if self.service else ""
        return f"[TAKEOVER] {self.host}{svc}"


@dataclass
class RunStats:
    """Rolling counters surfaced in the final summary."""

    wildcard_entries: int = 0
    plain_entries: int = 0
    subdomains_found: int = 0
    hosts_scanned: int = 0
    nuclei_findings: int = 0
    takeover_findings: int = 0
    errors: List[str] = field(default_factory=list)
