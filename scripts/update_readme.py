"""Fill the generated blocks of README.md from REAL data: the attack library and the saved demo scans.

    promptshield demo --no-banner -o docs/demo-results
    python scripts/update_readme.py

Every number in the README's generated blocks comes from docs/demo-results/*.json or the YAML library;
nothing is typed by hand. Run it again after changing attacks or the demo bots.

Built by Aryaveer Mankotia (https://github.com/Aryaveer009)
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from promptshield.attacks import load_attacks
from promptshield.models import Category

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "docs" / "demo-results"


def load(which: str) -> dict:
    return json.loads((RESULTS / f"demo-{which}.json").read_text(encoding="utf-8"))


def fmt(score: float | None) -> str:
    return "n/a" if score is None else f"{score:.1f}"


def stats_block() -> str:
    attacks = load_attacks()
    cats = len({a.category for a in attacks})
    return f"**{len(attacks)} attacks** across **{cats} categories**, every one mapped to an OWASP LLM code."


def library_block() -> str:
    attacks = load_attacks()
    counts = Counter(a.category for a in attacks)
    owasp = {c: sorted({a.owasp for a in attacks if a.category is c}) for c in Category}
    rows = ["| Category | Attacks | OWASP (2025) |", "|---|---:|---|"]
    for c in Category:
        rows.append(f"| {c.label} | {counts[c]} | {', '.join(owasp[c])} |")
    rows.append(f"| **Total** | **{len(attacks)}** | |")
    return "\n".join(rows)


def demo_table_block() -> str:
    v, h = load("vulnerable"), load("hardened")
    rows = [
        "| | Vulnerable demo bot | Hardened demo bot |",
        "|---|:---:|:---:|",
        f"| **Security score** | **{fmt(v['score'])} / 100** | **{fmt(h['score'])} / 100** |",
        f"| **Grade** | {v['grade']} | {h['grade']} |",
        f"| Attacks resisted | {v['passed']} / {v['total']} | {h['passed']} / {h['total']} |",
        f"| Attacks that succeeded | {v['failed']} | {h['failed']} |",
    ]
    vc = {c["label"]: c for c in v["categories"]}
    hc = {c["label"]: c for c in h["categories"]}
    for label, vcat in vc.items():
        hcat = hc[label]
        rows.append(
            f"| {label} | {fmt(vcat['score'])} ({vcat['passed']}/{vcat['passed'] + vcat['failed']}) "
            f"| {fmt(hcat['score'])} ({hcat['passed']}/{hcat['passed'] + hcat['failed']}) |"
        )
    return "\n".join(rows)


def gaps_block() -> str:
    h = load("hardened")
    failed = [f for f in h["findings"] if f["verdict"] == "fail"]
    failed.sort(key=lambda f: f["attack"]["id"])
    lines = [
        "| Attack | Severity | Why it still works |",
        "|---|---|---|",
    ]
    for f in failed:
        a = f["attack"]
        reason = f["hits"][0]["reason"] if f["hits"] else ""
        lines.append(f"| `{a['id']}` {a['title']} | {a['severity']} | {reason} |")
    return "\n".join(lines)


BLOCKS = {
    "stats": stats_block,
    "library-table": library_block,
    "demo-table": demo_table_block,
    "hardened-gaps": gaps_block,
}


def main() -> None:
    text = README.read_text(encoding="utf-8")
    for name, build in BLOCKS.items():
        pattern = re.compile(rf"(<!-- BEGIN:{name} -->\n).*?(\n<!-- END:{name} -->)", re.DOTALL)
        if not pattern.search(text):
            raise SystemExit(f"README is missing the {name!r} markers")
        block = build()
        text = pattern.sub(lambda m, block=block: m.group(1) + block + m.group(2), text)
    README.write_text(text, encoding="utf-8")
    print("README.md updated from real data")


if __name__ == "__main__":
    main()
