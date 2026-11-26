"""GUI-independent helpers (filtering, area x perspective roll-up, summary); unit-tested headless."""
from __future__ import annotations

from collections import Counter

from .models import STATUSES, PASS, FAIL, WARN, AREAS, ADMIN, USER

ORDER = {s: i for i, s in enumerate(STATUSES)}


def sort_results(results):
    return sorted(results, key=lambda r: (ORDER.get(r.status, 9), r.area, r.check_id, r.target))


def filter_results(results, status="ALL", perspective="ALL", area="ALL", text=""):
    q = (text or "").strip().lower()
    out = []
    for r in sort_results(results):
        if status != "ALL" and r.status != status:
            continue
        if perspective != "ALL" and r.perspective != perspective:
            continue
        if area != "ALL" and r.area != area:
            continue
        if q and q not in f"{r.title} {r.target} {r.actual} {r.check_id} {r.remediation}".lower():
            continue
        out.append(r)
    return out


def by_area(results):
    """Rows: one per (area, perspective) with status counts, in a stable order."""
    rows = []
    for area in AREAS:
        for persp in (ADMIN, USER):
            sub = [r for r in results if r.area == area and r.perspective == persp]
            if not sub:
                continue
            c = Counter(r.status for r in sub)
            rows.append({"area": area, "perspective": persp, "fail": c[FAIL], "warn": c[WARN], "pass": c[PASS],
                         "other": len(sub) - c[FAIL] - c[WARN] - c[PASS]})
    return rows


def summary(results):
    c = Counter(r.status for r in results)
    scored = c[PASS] + c[FAIL] + c[WARN]
    return c, (round(100 * c[PASS] / scored) if scored else 0)
