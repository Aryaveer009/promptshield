"""Report rendering: a self-contained HTML report and a JSON export."""

from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from promptshield.branding import REPO_URL, RESPONSIBLE_USE_NOTICE
from promptshield.fixes import CATEGORY_FIXES
from promptshield.judge import JUDGE_DISCLAIMER
from promptshield.models import ScanResult, Verdict
from promptshield.owasp import OWASP_LLM_TOP10, OWASP_URL, OWASP_VERSION

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "j2"], default=True),  # model output is hostile input
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def render_html(result: ScanResult) -> str:
    findings = sorted(result.findings, key=lambda f: (-f.attack.severity.rank, f.attack.id))
    failed = [f for f in findings if f.verdict is Verdict.FAIL]
    passed = [f for f in result.findings if f.verdict is Verdict.PASS]
    others = [f for f in result.findings if f.verdict in (Verdict.ERROR, Verdict.SKIPPED)]
    judged = [f for f in result.findings if f.judge is not None]

    score = result.score
    template = _ENV.get_template("report.html.j2")
    return template.render(
        result=result,
        failed=failed,
        passed=passed,
        others=others,
        judged=judged,
        score_text="n/a" if score is None else f"{score:.0f}",
        gauge_fill=0 if score is None else round(score, 1),
        owasp_all=OWASP_LLM_TOP10,
        owasp_by_code={o.code: o for o in result.owasp},
        owasp_url=OWASP_URL,
        owasp_version=OWASP_VERSION,
        category_fixes={c.value: fix for c, fix in CATEGORY_FIXES.items()},
        judge_disclaimer=JUDGE_DISCLAIMER,
        repo_url=REPO_URL,
        notice=RESPONSIBLE_USE_NOTICE,
    )


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"


def write_reports(
    result: ScanResult,
    out_dir: Path,
    *,
    stem: str | None = None,
    formats: tuple[str, ...] = ("html", "json"),
) -> list[Path]:
    """Write the requested report formats; returns the paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    base = stem or f"promptshield-{_slug(result.target.name)}-{result.started_at:%Y%m%d-%H%M%S}"
    written: list[Path] = []
    if "html" in formats:
        path = out_dir / f"{base}.html"
        path.write_text(render_html(result), encoding="utf-8")
        written.append(path)
    if "json" in formats:
        path = out_dir / f"{base}.json"
        path.write_text(render_json(result), encoding="utf-8")
        written.append(path)
    return written
