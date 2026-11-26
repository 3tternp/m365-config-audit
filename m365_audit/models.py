"""Shared result model."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

PASS, FAIL, WARN, MANUAL, ERROR, INFO = "PASS", "FAIL", "WARN", "MANUAL", "ERROR", "INFO"
STATUSES = (FAIL, WARN, ERROR, MANUAL, INFO, PASS)
ADMIN, USER = "Admin", "User"
AREAS = ("Teams", "Exchange", "SharePoint", "OneDrive", "Tenant")


@dataclass
class Result:
    check_id: str
    perspective: str      # "Admin" or "User": which sign-in produced this finding
    area: str             # Teams / Exchange / SharePoint / OneDrive / Tenant
    title: str
    status: str
    actual: Any = ""
    expected: Any = ""
    remediation: str = ""
    target: str = ""      # team, mailbox, site, domain ... (blank = tenant/account wide)
    reference: str = ""

    def to_dict(self):
        d = asdict(self)
        d["actual"], d["expected"] = str(d["actual"]), str(d["expected"])
        return d


def make(check_id, perspective, area, title, status, actual="", expected="", remediation="", target="", reference=""):
    return Result(check_id, perspective, area, title, status, actual, expected,
                  "" if status == PASS else remediation, target, reference)


def short(items, limit=10):
    items = [str(i) for i in items]
    if len(items) <= limit:
        return "; ".join(items)
    return "; ".join(items[:limit]) + f" ... (+{len(items) - limit} more, total {len(items)})"
