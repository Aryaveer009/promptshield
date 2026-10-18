"""Attack library loading: built-in YAML files plus optional user-supplied directories."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from promptshield.models import Attack, Category, Severity


class AttackLibraryError(Exception):
    """An attack file is malformed or an ID is duplicated."""


def builtin_library_dir() -> Path:
    return Path(str(resources.files("promptshield.attacks").joinpath("library")))


def _yaml_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted([*path.glob("*.yaml"), *path.glob("*.yml")])
    raise AttackLibraryError(f"Attack path does not exist: {path}")


def load_attack_file(path: Path) -> list[Attack]:
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AttackLibraryError(f"{path}: cannot read YAML: {exc}") from exc
    entries = raw.get("attacks") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise AttackLibraryError(f"{path}: expected a top-level `attacks:` list.")
    attacks: list[Attack] = []
    for index, entry in enumerate(entries, start=1):
        try:
            attacks.append(Attack.model_validate(entry))
        except ValidationError as exc:
            ident = entry.get("id", f"#{index}") if isinstance(entry, dict) else f"#{index}"
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
            )
            raise AttackLibraryError(f"{path}: attack {ident}: {problems}") from exc
    return attacks


def load_attacks(extra_paths: Sequence[Path] = (), *, include_builtin: bool = True) -> list[Attack]:
    """Load and validate attacks. Raises ``AttackLibraryError`` on any problem or duplicate id."""
    paths: list[Path] = []
    if include_builtin:
        paths.extend(_yaml_files(builtin_library_dir()))
    for extra in extra_paths:
        paths.extend(_yaml_files(extra))

    seen: dict[str, Path] = {}
    attacks: list[Attack] = []
    for path in paths:
        for attack in load_attack_file(path):
            if attack.id in seen:
                raise AttackLibraryError(
                    f"Duplicate attack id {attack.id} in {path} (first defined in {seen[attack.id]})"
                )
            seen[attack.id] = path
            attacks.append(attack)
    return attacks


def filter_attacks(
    attacks: Iterable[Attack],
    *,
    categories: Sequence[Category] = (),
    ids: Sequence[str] = (),
    exclude_ids: Sequence[str] = (),
    min_severity: Severity | None = None,
) -> list[Attack]:
    wanted_ids = {i.upper() for i in ids}
    excluded = {i.upper() for i in exclude_ids}
    selected = []
    for attack in attacks:
        if categories and attack.category not in categories:
            continue
        if wanted_ids and attack.id not in wanted_ids:
            continue
        if attack.id in excluded:
            continue
        if min_severity and attack.severity.rank < min_severity.rank:
            continue
        selected.append(attack)
    return selected
