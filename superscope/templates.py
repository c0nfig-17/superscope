"""Fetch the rix4uni/nucleihub-templates collection and locate the -t path."""
from __future__ import annotations

import logging
import os
from typing import Optional

from .util import ensure_repo

log = logging.getLogger("superscope.templates")


def resolve_templates_dir(config, workdir: str) -> Optional[str]:
    """Return the directory to pass to ``nuclei -t``.

    Uses ``templates.local_path`` if set, otherwise clones/updates the repo
    into ``workdir/templates``. The collector nests the actual ``.yaml`` files
    under a ``nucleihub-templates`` subdirectory (configurable via
    ``templates.subdir``); we point Nuclei at that subdir when it exists so it
    does not waste time walking the repo's README/tooling.
    """
    local = config.get("templates.local_path")
    if local:
        local = os.path.expanduser(local)
        if not os.path.isdir(local):
            raise FileNotFoundError(f"templates.local_path does not exist: {local}")
        base = local
    else:
        dest = os.path.join(workdir, "templates")
        base = ensure_repo(
            config.get("templates.repo"),
            dest,
            update=bool(config.get("templates.update", True)),
        )
        if not base:
            log.error("Could not obtain the Nuclei templates repository")
            return None

    subdir = config.get("templates.subdir") or ""
    if subdir:
        nested = os.path.join(base, subdir)
        if os.path.isdir(nested):
            base = nested
        else:
            log.warning("templates.subdir %r not found under %s; using repo root",
                        subdir, base)

    count = _count_templates(base)
    if count == 0:
        log.warning("No .yaml templates found under %s", base)
    else:
        log.info("Using %d Nuclei templates from %s", count, base)
    return base


def _count_templates(base: str) -> int:
    total = 0
    for _root, _dirs, files in os.walk(base):
        total += sum(1 for f in files if f.endswith((".yaml", ".yml")))
        if total > 5000:  # cheap upper bound; no need to count them all
            break
    return total
