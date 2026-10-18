"""Generate assets/banner.svg for the README (no dependencies, deterministic).

    python scripts/generate_banner.py

The attack count in the banner is read from the real attack library, never typed by hand.

Built by Aryaveer Mankotia (https://github.com/Aryaveer009)
"""

from __future__ import annotations

from pathlib import Path

from promptshield.attacks import load_attacks

OUT = Path(__file__).resolve().parent.parent / "assets" / "banner.svg"
WIDTH, HEIGHT = 1280, 320


def build() -> str:
    n_attacks = len(load_attacks())
    chips = ["LLM01", "LLM02", "LLM05", "LLM06", "LLM07"]
    chip_svg = []
    x = 304
    for code in chips:
        chip_svg.append(
            f'<rect x="{x}" y="226" width="86" height="30" rx="15" fill="#ffffff" fill-opacity="0.10" '
            f'stroke="#a5b4fc" stroke-opacity="0.55"/>'
            f'<text x="{x + 43}" y="246" text-anchor="middle" font-size="14" font-weight="600" '
            f'fill="#e0e7ff">{code}</text>'
        )
        x += 98

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-label="PromptShield: security testing for LLM applications, built by Aryaveer Mankotia">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1020"/>
      <stop offset="0.55" stop-color="#2a2570"/>
      <stop offset="1" stop-color="#0e7490"/>
    </linearGradient>
    <linearGradient id="title" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#a5f3fc"/>
    </linearGradient>
    <linearGradient id="scan" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#67e8f9" stop-opacity="0"/>
      <stop offset="0.5" stop-color="#67e8f9" stop-opacity="0.55"/>
      <stop offset="1" stop-color="#67e8f9" stop-opacity="0"/>
    </linearGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">
      <path d="M32 0H0V32" fill="none" stroke="#ffffff" stroke-opacity="0.05"/>
    </pattern>
    <clipPath id="shieldClip"><path d="M150 56 70 90v68c0 56 34 96 80 116 46-20 80-60 80-116V90L150 56z"/></clipPath>
  </defs>

  <rect width="{WIDTH}" height="{HEIGHT}" rx="22" fill="url(#bg)"/>
  <rect width="{WIDTH}" height="{HEIGHT}" rx="22" fill="url(#grid)"/>

  <g font-family="'Segoe UI', -apple-system, 'Helvetica Neue', Arial, sans-serif">
    <!-- shield -->
    <path d="M150 56 70 90v68c0 56 34 96 80 116 46-20 80-60 80-116V90L150 56z" fill="#ffffff" fill-opacity="0.10" stroke="#ffffff" stroke-width="5" stroke-linejoin="round"/>
    <g clip-path="url(#shieldClip)">
      <rect x="60" y="60" width="180" height="46" fill="url(#scan)">
        <animateTransform attributeName="transform" type="translate" values="0 -20; 0 190; 0 -20" dur="4s" repeatCount="indefinite"/>
      </rect>
    </g>
    <path d="M110 164 138 192 192 128" fill="none" stroke="#67e8f9" stroke-width="13" stroke-linecap="round" stroke-linejoin="round"/>

    <!-- text -->
    <text x="300" y="138" font-size="76" font-weight="800" fill="url(#title)" letter-spacing="1">PromptShield</text>
    <text x="304" y="184" font-size="26" fill="#c7d2fe">Attack your own LLM app before someone else does.</text>
    <text x="304" y="214" font-size="17" fill="#a5b4fc" fill-opacity="0.9">{n_attacks} attacks · canary-based detection · OWASP Top 10 for LLM Applications report</text>
    {"".join(chip_svg)}

    <text x="{WIDTH - 40}" y="{HEIGHT - 28}" text-anchor="end" font-size="18" font-weight="600" fill="#ffffff" fill-opacity="0.92">Built by Aryaveer Mankotia</text>
  </g>
</svg>
"""


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT}")
