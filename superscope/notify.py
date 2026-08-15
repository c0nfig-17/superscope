"""Route findings to ProjectDiscovery Notify — two independent channels.

Notify (https://github.com/projectdiscovery/notify) fans a text payload out to
whatever webhooks its *provider-config* names (Slack, Discord, Telegram, a raw
webhook, ...). superscope keeps two channels so the two kinds of result land in
different places:

* ``findings`` — Nuclei vulnerabilities.
* ``takeover`` — subzy subdomain takeovers, on a DIFFERENT webhook.

The webhook URLs never live in superscope's config: each channel only points
Notify at its own provider-config file (given directly, or via the environment
variable named in config). The payload is plain, line-oriented text piped to
``notify -bulk`` on stdin.
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import List, Optional, Sequence

from .models import NucleiFinding, TakeoverFinding
from .util import have_binary

log = logging.getLogger("superscope.notify")

CHUNK = 40  # lines per Notify message, so a big batch is not truncated


def _resolve_provider_config(config, channel: str) -> Optional[str]:
    env_name = config.get(f"notify.{channel}.provider_config_env")
    if env_name:
        val = os.environ.get(env_name)
        if val:
            return os.path.expanduser(val.strip())
    explicit = config.get(f"notify.{channel}.provider_config")
    if explicit:
        return os.path.expanduser(explicit)
    return None


def _send(config, channel: str, lines: Sequence[str], header: str) -> bool:
    """Pipe ``lines`` to Notify on the given channel. Returns True if sent."""
    if not lines:
        return False
    if not config.get("notify.enabled", True):
        log.info("Notify disabled — would have sent %d line(s) to '%s'",
                 len(lines), channel)
        return False

    binary = config.get("notify.binary", "notify")
    if not have_binary(binary):
        log.warning("notify not installed — %d '%s' result(s) not delivered "
                    "(install: go install github.com/projectdiscovery/notify/"
                    "cmd/notify@latest)", len(lines), channel)
        return False

    provider_config = _resolve_provider_config(config, channel)
    if not provider_config:
        log.warning("No provider-config for the '%s' channel — set "
                    "notify.%s.provider_config or its *_env var. "
                    "%d result(s) not delivered.", channel, channel, len(lines))
        return False
    if not os.path.isfile(provider_config):
        log.warning("provider-config for '%s' not found at %s — %d result(s) "
                    "not delivered.", channel, provider_config, len(lines))
        return False

    provider_id = config.get(f"notify.{channel}.provider_id")

    ok = True
    for i in range(0, len(lines), CHUNK):
        block = lines[i:i + CHUNK]
        payload = header + "\n" + "\n".join(block) if i == 0 else "\n".join(block)
        cmd = [binary, "-provider-config", provider_config]
        if config.get("notify.bulk", True):
            cmd.append("-bulk")
        if provider_id:
            cmd += ["-id", provider_id]
        try:
            proc = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            log.error("notify timed out on the '%s' channel", channel)
            ok = False
            continue
        if proc.returncode != 0:
            log.warning("notify (%s) exited %d: %s", channel, proc.returncode,
                        proc.stderr.strip()[:300])
            ok = False
    if ok:
        log.info("Sent %d line(s) to the '%s' channel", len(lines), channel)
    return ok


def notify_findings(config, findings: Sequence[NucleiFinding],
                    context: str = "") -> bool:
    """Send Nuclei findings to the findings channel."""
    if not findings:
        return False
    header = "🔎 superscope — Nuclei findings"
    if context:
        header += f" ({context})"
    lines: List[str] = [f.as_line() for f in findings]
    return _send(config, "findings", lines, header)


def notify_takeovers(config, takeovers: Sequence[TakeoverFinding]) -> bool:
    """Send subzy takeovers to the takeover channel (different webhook)."""
    if not takeovers:
        return False
    header = "🚨 superscope — subdomain takeover(s) VULNERABLE"
    lines: List[str] = [t.as_line() for t in takeovers]
    return _send(config, "takeover", lines, header)
