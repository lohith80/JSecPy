"""Rule registry. Built-in rules self-register via @register on import."""

from __future__ import annotations

import importlib
import pkgutil

from .base import Rule, TaintCache, TaintSinkRule  # noqa: F401

_REGISTRY: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define an id")
    if cls.id in _REGISTRY:
        raise ValueError(f"duplicate rule id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def load_builtin_rules() -> list[Rule]:
    """Import every sibling module so their @register decorators run."""
    package = __name__
    for mod in pkgutil.iter_modules(__path__):
        if mod.name in {"base"}:
            continue
        importlib.import_module(f"{package}.{mod.name}")
    return [cls() for cls in _REGISTRY.values()]


def registry() -> dict[str, type[Rule]]:
    return dict(_REGISTRY)
