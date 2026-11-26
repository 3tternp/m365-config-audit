"""Helpers shared by the area modules."""
from __future__ import annotations

from .graph import GraphError
from .models import WARN, ERROR, make


def guarded(check_id, perspective, area, title, fn, log=lambda m: None, need=""):
    """Run fn() -> list[Result]; turn Graph/permission failures into a clear finding instead of crashing the scan."""
    try:
        return fn()
    except GraphError as e:
        log(f"[{perspective}/{area}] {title}: {e}")
        if e.denied:
            return [make(check_id, perspective, area, title, WARN, "access denied for this account",
                         "readable", f"Not checked: the {perspective.lower()} sign-in lacks access"
                                     + (f" ({need})" if need else "") + ". Grant the permission/consent or use another account.")]
        return [make(check_id, perspective, area, title, ERROR, f"{e.status} {e.code}", "", e.message[:160])]
    except Exception as e:  # never let one check kill the scan
        log(f"[{perspective}/{area}] {title}: {type(e).__name__}: {e}")
        return [make(check_id, perspective, area, title, ERROR, f"{type(e).__name__}: {str(e)[:120]}", "")]


def first(data):
    """Graph sometimes returns a single object, sometimes a one-item collection."""
    if isinstance(data, dict) and "value" in data:
        return (data["value"] or [{}])[0]
    return data or {}


def aslist(x):
    """PowerShell's ConvertTo-Json collapses 1-element arrays to objects and empty to null."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def domain_of(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
