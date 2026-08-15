# superscope

**Scope-driven scanning for Bugcrowd & HackerOne.** superscope reads the public
program scope published at [`rix4uni/scope`](https://github.com/rix4uni/scope),
splits every in-scope entry into *wildcard* and *concrete* targets, and runs a
fixed pipeline over each — subdomain enumeration, a full Nuclei sweep with the
[`rix4uni/nucleihub-templates`](https://github.com/rix4uni/nucleihub-templates)
collection, and a subdomain-takeover check — routing anything interesting to
[ProjectDiscovery Notify](https://github.com/projectdiscovery/notify).

> ⚠️ **Authorized use only.** Only scan programs and assets you are authorized
> to test under the relevant bug-bounty program's rules. In-scope on a platform
> is not the same as permission to run every check at any volume — mind each
> program's testing policy and rate limits. You are responsible for how you use
> this tool.

---

## The flow

```
rix4uni/scope  ──►  in-scope entries for bugcrowd + hackerone
                         │
        ┌────────────────┴───────────────────┐
        │ wildcard (*.example.com)            │ non-wildcard (api.example.com)
        ▼                                     ▼
   subfinder (enumerate subdomains)           │
        ▼                                     │
   ┌── blocks of 30 hosts ──┐                 ┌── blocks of 30 hosts ──┐
   ▼                        ▼                 ▼                        ▼
   nuclei (all templates)  …                  nuclei (all templates)  …
        │                                     │
        ▼                                     ▼
   notify ──► FINDINGS webhook  ◄─────────────┘
        │
        └─ all discovered hosts ─► subzy ─► notify ─► TAKEOVER webhook (different)
```

- **Wildcard entries** (`*.example.com`, `*-prod.example.com`, …) → enumerate
  subdomains with **subfinder**, then Nuclei-scan the results **in blocks of 30**
  so a large target never fires everything at once. Findings go to the
  **findings** Notify channel.
- **Non-wildcard entries** (`api.example.com`) → Nuclei directly (also in blocks
  of 30). Findings go to the **findings** channel.
- **Every host discovered** (enumerated subdomains + concrete hosts) → **subzy**
  for subdomain takeover. **Only VULNERABLE** results are sent, to a **separate
  takeover** Notify channel (a different webhook).

The block size, severities, rate limits and every stage toggle are configurable.

---

## Install

```bash
git clone https://github.com/c0nfig-17/superscope
cd superscope
./install.sh          # one command: Python deps + subfinder, nuclei, subzy, notify
```

`./install.sh` is a single, no-sudo command. It installs the Python deps and
the four tools, and — **only if `go` isn't already on your PATH** — drops a
local Go toolchain into `~/.local/go` first, so you don't need to install Go
yourself. Tool binaries land in `~/go/bin`; the script prints the one `export
PATH=…` line to add to your shell rc.

Everything is best-effort and idempotent: any binary it can't install is
reported, and superscope then **skips that stage at runtime** with an install
hint rather than crashing, so a partial toolbox still runs the stages it can.

Requirements: Python 3.9+, `git`, and `curl`/`wget`. Nuclei needs its
templates — superscope fetches `nucleihub-templates` automatically, and
`install.sh` also runs `nuclei -update-templates` for the official set.

---

## Configure

```bash
cp config.yaml.example config.yaml   # install.sh does this for you
$EDITOR config.yaml
```

Everything has a working default (see `config.yaml.example` for the annotated
list). The parts you'll usually touch:

| Setting | What it does |
| --- | --- |
| `scope.platforms` | `["bugcrowd", "hackerone"]` — which programs to pull. |
| `scope.include_roots` / `exclude_roots` | Narrow to / exclude specific registrable domains. |
| `flow.batch_size` | Nuclei block size (default **30**). |
| `flow.run_subfinder` / `run_nuclei` / `run_subzy` | Turn stages off. |
| `nuclei.severities` | Which severities are worth a notification (`[]` = all). |
| `nuclei.rate_limit` / `concurrency` | Keep scans gentle. |

### Notify — two webhooks

superscope keeps **two independent Notify channels** so findings and takeovers
land in different places. The webhook URLs live in Notify's own
*provider-config* files — never in superscope's config, which only points at
them.

1. Create two provider-configs (see the
   [Notify docs](https://github.com/projectdiscovery/notify#provider-config)),
   e.g. `~/.config/notify/findings.yaml` and `~/.config/notify/takeover.yaml`,
   each with its own webhook.
2. Point superscope at them — either paths in `config.yaml` or via env vars:

   ```bash
   export SUPERSCOPE_NOTIFY_FINDINGS=~/.config/notify/findings.yaml
   export SUPERSCOPE_NOTIFY_TAKEOVER=~/.config/notify/takeover.yaml
   ```

The `*_env` var wins over the in-file `provider_config` path when both are set.

---

## Run

```bash
# See exactly what would be scanned, without launching anything:
python3 -m superscope --dry-run

# Full run:
python3 -m superscope

# Narrow it down while iterating:
python3 -m superscope --platforms hackerone --batch-size 20 --no-subzy
python3 -m superscope --no-notify -v          # loud, but stay quiet on the wire
```

### CLI

| Flag | Effect |
| --- | --- |
| `--config PATH` | Config file (default `./config.yaml` or `$SUPERSCOPE_CONFIG`). |
| `--platforms a,b` | Override `scope.platforms`. |
| `--workdir DIR` | Where checkouts + temp lists go (default `./output`). |
| `--batch-size N` | Override the Nuclei block size. |
| `--no-subfinder` | Scan apex domains only, skip enumeration. |
| `--no-nuclei` / `--no-subzy` | Skip that stage. |
| `--no-notify` | Do everything, deliver nothing. |
| `--dry-run` | Resolve scope, print the plan, launch nothing. |
| `-v` / `-q` | Verbose / quiet logging. |

---

## How scope is parsed

Entries come from `data/<Platform>/<platform>_inscope.txt` in `rix4uni/scope`,
one host per line. An entry is a **wildcard** if it contains `*`; otherwise it's
a concrete host. For wildcards the **registrable domain** is derived
(`*-prod.arlo.com` → `arlo.com`, `portal.*.clearpay.co.uk` → `clearpay.co.uk`)
and handed to subfinder. Out-of-scope files are read only to build an exclusion
set, so a host that is both in- and out-of-scope is never touched. Install
`tldextract` for full Public Suffix List accuracy; without it superscope uses a
built-in suffix set that covers the common multi-label ccTLDs.

---

## Layout

```
superscope/
  cli.py         argument parsing + overrides
  config.py      defaults <- config.yaml <- env
  scope.py       fetch + parse + classify rix4uni/scope
  templates.py   fetch nucleihub-templates, locate the -t path
  tools.py       subfinder / nuclei / subzy wrappers (+ output parsing)
  notify.py      two Notify channels (findings, takeover)
  pipeline.py    the orchestrator that runs the whole flow
  util.py        git checkouts, registrable-domain math, batching
config.yaml.example
install.sh
```
