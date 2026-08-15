"""superscope — Bugcrowd / HackerOne scope-driven scanning pipeline.

superscope wires together a small set of best-of-breed recon tools around the
public scope data published at https://github.com/rix4uni/scope and the Nuclei
template collection at https://github.com/rix4uni/nucleihub-templates:

    scope  ->  split wildcard / non-wildcard
        wildcard entries      -> subfinder -> nuclei (all templates) -> notify
        non-wildcard entries  ->              nuclei (all templates) -> notify
        every discovered host -> subzy (takeover) -> notify (2nd webhook)

The heavy lifting is done by the external binaries (subfinder, nuclei, subzy,
notify); this package is the orchestrator that fetches scope, classifies
targets, batches work into blocks so scans stay gentle, and routes findings to
the right Notify channel.
"""

__version__ = "0.1.0"
