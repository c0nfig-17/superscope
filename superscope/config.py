"""Configuration loading for superscope.

Three layers, later overriding earlier:

1. Built-in :data:`DEFAULTS` — safe, non-secret, work out of the box.
2. A YAML file (``--config``, ``$SUPERSCOPE_CONFIG`` or ``./config.yaml``).
3. A few environment variables for values that must never live in a file.

Secrets (API keys, and — most importantly — the Notify provider configs that
hold your webhook URLs) are NEVER stored in this file. The file only names the
resources; the webhook URLs stay inside Notify's own provider-config YAML, and
the file paths can be given directly or through an environment variable.
"""
from __future__ import annotations

import copy
import os
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - dependency missing
    yaml = None


DEFAULTS: Dict[str, Any] = {
    # ------------------------------------------------------------------ scope
    "scope": {
        # Where the rix4uni/scope data comes from. By default we shallow-clone
        # it into workdir; point `local_path` at an existing checkout to run
        # fully offline / from your own fork.
        "repo": "https://github.com/rix4uni/scope",
        "local_path": "",
        "platforms": ["bugcrowd", "hackerone"],
        # Only in-scope entries are scanned. Out-of-scope files are read solely
        # to build an exclusion set so we never touch a forbidden host.
        "respect_outofscope": True,
        # Optional allow/deny post-filters on the registrable domain.
        "include_roots": [],   # if non-empty, keep only entries under these
        "exclude_roots": [],   # always drop entries under these
    },
    # -------------------------------------------------------------- templates
    "templates": {
        "repo": "https://github.com/rix4uni/nucleihub-templates",
        "local_path": "",
        # Subdirectory inside the repo that actually holds the .yaml templates.
        # The collector nests them under nucleihub-templates/.
        "subdir": "nucleihub-templates",
        "update": True,  # git pull if the checkout already exists
    },
    # ------------------------------------------------------------------- flow
    "flow": {
        "workdir": "./output",
        # Enumerated subdomains are scanned by Nuclei in blocks of this size so
        # a huge wildcard target does not fire thousands of requests at once.
        "batch_size": 30,
        # Which stages run. Handy for narrowing a run down while iterating.
        "run_subfinder": True,
        "run_nuclei": True,
        "run_subzy": True,
        "dry_run": False,  # resolve scope + print the plan, launch nothing
    },
    # -------------------------------------------------------------- subfinder
    "subfinder": {
        "binary": "subfinder",
        "extra_args": ["-silent", "-all"],
        "timeout_seconds": 900,
        # subfinder reads provider API keys from its own config; we only name
        # the file so nothing secret lives here.
        "provider_config": "",
    },
    # ----------------------------------------------------------------- nuclei
    "nuclei": {
        "binary": "nuclei",
        # -t <templates dir> is injected by the pipeline; put everything else
        # here. Keep it silent + JSONL so we can parse findings reliably.
        "extra_args": ["-silent", "-jsonl", "-no-color"],
        # Severities worth a notification. Empty list = notify on everything.
        "severities": ["low", "medium", "high", "critical"],
        "rate_limit": 150,        # requests/sec ceiling passed as -rl
        "concurrency": 25,        # templates in parallel, passed as -c
        "timeout_seconds": 3600,
    },
    # ------------------------------------------------------------------ subzy
    "subzy": {
        "binary": "subzy",
        # subzy run --targets <file>; these flags are appended.
        "extra_args": ["--hide_fails", "--concurrency", "50"],
        "timeout_seconds": 1800,
    },
    # ----------------------------------------------------------------- notify
    # Two independent channels, each pointing Notify at its own provider-config
    # (so vulnerabilities and takeovers can go to different webhooks). The
    # webhook URLs live in those provider-config files, never here.
    "notify": {
        "enabled": True,
        "binary": "notify",
        "bulk": True,
        # Channel 1: Nuclei findings.
        "findings": {
            "provider_config_env": "SUPERSCOPE_NOTIFY_FINDINGS",
            "provider_config": "",
            "provider_id": "",     # optional `notify -id` profile selector
        },
        # Channel 2: subzy takeovers — a DIFFERENT webhook.
        "takeover": {
            "provider_config_env": "SUPERSCOPE_NOTIFY_TAKEOVER",
            "provider_config": "",
            "provider_id": "",
        },
    },
}


class Config:
    """Thin wrapper over the merged config dict with dotted-path access."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data

    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> Dict[str, Any]:
        val = self.data.get(name, {})
        return val if isinstance(val, dict) else {}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], val)
        else:
            out[key] = copy.deepcopy(val)
    return out


def _default_config_path() -> Optional[str]:
    env_path = os.environ.get("SUPERSCOPE_CONFIG")
    if env_path:
        return env_path
    for candidate in ("config.yaml", "config.yml"):
        if os.path.isfile(candidate):
            return candidate
    return None


def _boolenv(name: str) -> Optional[bool]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def apply_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
    """Apply the small set of non-secret env overrides."""
    out = copy.deepcopy(data)

    workdir = os.environ.get("SUPERSCOPE_WORKDIR")
    if workdir:
        out.setdefault("flow", {})["workdir"] = workdir

    dry = _boolenv("SUPERSCOPE_DRY_RUN")
    if dry is not None:
        out.setdefault("flow", {})["dry_run"] = dry

    notify_enabled = _boolenv("SUPERSCOPE_NOTIFY")
    if notify_enabled is not None:
        out.setdefault("notify", {})["enabled"] = notify_enabled

    return out


def load_config(path: Optional[str] = None) -> Config:
    """Load config: defaults <- file <- env overrides."""
    data = copy.deepcopy(DEFAULTS)

    cfg_path = path or _default_config_path()
    if cfg_path:
        if yaml is None:
            raise RuntimeError(
                "A config file was provided but PyYAML is not installed. "
                "Install it with `pip install pyyaml`."
            )
        with open(cfg_path, "r", encoding="utf-8") as fh:
            file_data = yaml.safe_load(fh) or {}
        if not isinstance(file_data, dict):
            raise ValueError(f"Config file {cfg_path} must contain a YAML mapping")
        data = _deep_merge(data, file_data)

    return Config(apply_env_overrides(data))
