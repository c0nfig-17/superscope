"""Small shared helpers: git checkouts, domain math, batching."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Iterable, Iterator, List, Optional, Sequence, TypeVar

log = logging.getLogger("superscope.util")

T = TypeVar("T")

# A compact multi-label public-suffix set. Not exhaustive, but it covers the
# ccTLD second levels that actually show up in bug-bounty scope data (co.uk,
# com.br, ...). When the `tldextract` package is installed we defer to it for
# full Public Suffix List accuracy.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "com.br", "com.mx", "com.ar", "com.co", "com.tr", "com.cn",
    "co.jp", "or.jp", "ne.jp", "co.in", "co.nz", "co.za", "co.kr",
    "com.sg", "com.hk", "com.tw", "com.my", "com.ua", "com.pl",
}

try:  # optional, for full PSL correctness
    import tldextract  # type: ignore

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline, cached PSL
except Exception:  # pragma: no cover - optional dependency
    _EXTRACT = None


def registrable_domain(entry: str) -> str:
    """Best-effort registrable domain for a scope entry.

    Handles wildcards anywhere in the name by dropping every label that
    contains ``*`` before resolving the eTLD+1::

        *.example.com          -> example.com
        *-prod.example.com     -> example.com
        portal.*.example.co.uk -> example.co.uk
    """
    host = entry.strip().lower().strip(".")
    if not host:
        return ""
    labels = [l for l in host.split(".") if l and "*" not in l]
    if len(labels) < 2:
        return ""
    clean = ".".join(labels)

    if _EXTRACT is not None:
        ext = _EXTRACT(clean)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return ""

    # Fallback: check the two-label suffix set, else take the last two labels.
    if len(labels) >= 3:
        last_two = ".".join(labels[-2:])
        if last_two in _MULTI_SUFFIXES:
            return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def wildcard_to_regex(pattern: str) -> re.Pattern:
    """Compile a scope wildcard (``*-prod.example.com``) into a host matcher."""
    escaped = re.escape(pattern.lower().strip())
    escaped = escaped.replace(r"\*", r"[a-z0-9_\-]*")
    return re.compile(rf"^{escaped}$")


def batched(items: Sequence[T], size: int) -> Iterator[List[T]]:
    """Yield consecutive chunks of ``size`` items (last one may be smaller)."""
    if size <= 0:
        yield list(items)
        return
    for i in range(0, len(items), size):
        yield list(items[i:i + size])


def dedupe(items: Iterable[T]) -> List[T]:
    """Order-preserving de-duplication."""
    seen = set()
    out: List[T] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None


def ensure_repo(repo_url: str, dest: str, update: bool = True,
                timeout: int = 600) -> Optional[str]:
    """Shallow-clone ``repo_url`` into ``dest`` (or ``git pull`` if it exists).

    Returns ``dest`` on success, ``None`` on failure (logged, non-fatal) so a
    transient network problem degrades to whatever checkout is already on disk.
    """
    if not have_binary("git"):
        log.error("git is not installed; cannot fetch %s", repo_url)
        return dest if os.path.isdir(dest) else None

    if os.path.isdir(os.path.join(dest, ".git")):
        if not update:
            return dest
        log.info("Updating %s", dest)
        rc = _run_git(["-C", dest, "pull", "--ff-only", "--depth", "1"], timeout)
        return dest if os.path.isdir(dest) else None if rc != 0 else dest

    os.makedirs(os.path.dirname(os.path.abspath(dest)) or ".", exist_ok=True)
    log.info("Cloning %s -> %s", repo_url, dest)
    rc = _run_git(["clone", "--depth", "1", repo_url, dest], timeout)
    if rc != 0:
        log.error("Failed to clone %s", repo_url)
        return None
    return dest


def _run_git(args: List[str], timeout: int) -> int:
    try:
        proc = subprocess.run(
            ["git", *args],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, text=True,
        )
        if proc.returncode != 0:
            log.debug("git %s failed: %s", " ".join(args), proc.stdout.strip())
        return proc.returncode
    except subprocess.TimeoutExpired:
        log.error("git %s timed out after %ss", " ".join(args), timeout)
        return 1
    except Exception as exc:  # pragma: no cover
        log.error("git %s errored: %s", " ".join(args), exc)
        return 1
