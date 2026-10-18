"""Adapter that calls a Python function in-process (great for testing your own app code)."""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from promptshield.adapters.base import TargetAdapter, TargetError, fold_documents, parse_tool_calls
from promptshield.models import TargetRequest, TargetResponse

_TEXT_KEYS = ("text", "response", "output", "answer", "content", "message", "reply")


def load_callable(spec: str, base_dir: Path | None = None) -> Callable[..., Any]:
    """Resolve ``package.module:function`` or ``path/to/file.py:function``."""
    module_part, sep, func_name = spec.rpartition(":")
    if not sep or not module_part or not func_name:
        raise TargetError(f"Invalid callable {spec!r}; expected 'module:function'.")
    try:
        if module_part.endswith(".py") or "/" in module_part:
            path = Path(module_part)
            if not path.is_absolute() and base_dir is not None:
                path = base_dir / path
            module_spec = importlib.util.spec_from_file_location(path.stem, path)
            if module_spec is None or module_spec.loader is None:
                raise TargetError(f"Cannot load Python file {path}")
            module = importlib.util.module_from_spec(module_spec)
            sys.modules[path.stem] = module
            module_spec.loader.exec_module(module)
        else:
            cwd = str(Path.cwd())
            if cwd not in sys.path:
                sys.path.insert(0, cwd)
            module = importlib.import_module(module_part)
        func = getattr(module, func_name)
    except TargetError:
        raise
    except Exception as exc:  # import errors, missing file, missing attribute...
        raise TargetError(f"Cannot import {spec!r}: {type(exc).__name__}: {exc}") from exc
    if not callable(func):
        raise TargetError(f"{spec!r} is not callable.")
    return func  # type: ignore[no-any-return]


def normalize_result(result: Any) -> TargetResponse:
    if isinstance(result, TargetResponse):
        return result
    if isinstance(result, str):
        return TargetResponse(text=result)
    if isinstance(result, dict):
        text = next((str(result[k]) for k in _TEXT_KEYS if k in result), "")
        return TargetResponse(text=text, tool_calls=parse_tool_calls(result.get("tool_calls")))
    return TargetResponse(text=str(result))


class CallableAdapter(TargetAdapter):
    kind = "callable"

    def __init__(self, func: Callable[..., Any], name: str = "python-callable") -> None:
        super().__init__(name)
        self._func = func
        try:
            params = inspect.signature(func).parameters
        except (TypeError, ValueError):
            params = {}  # type: ignore[assignment]
        self._accepts_documents = "documents" in params or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        )

    def describe(self) -> str:
        module = getattr(self._func, "__module__", "?")
        qualname = getattr(self._func, "__qualname__", repr(self._func))
        return f"Python callable {module}:{qualname}"

    def send(self, request: TargetRequest) -> TargetResponse:
        try:
            if self._accepts_documents:
                result = self._func(request.message, documents=list(request.documents))
            else:
                result = self._func(fold_documents(request))
        except Exception as exc:
            raise TargetError(f"Target raised {type(exc).__name__}: {exc}") from exc
        return normalize_result(result)
