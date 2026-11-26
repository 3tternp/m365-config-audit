"""Scan orchestration: runs the admin and/or employee perspective across the selected areas."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import teams, exchange, sharepoint, onedrive, tenant, psrunner
from .common import guarded
from .models import AREAS, ADMIN, USER, WARN, make


@dataclass
class ScanOptions:
    areas: tuple = AREAS
    use_powershell: bool = True
    max_teams: int = 200
    max_items: int = 150
    admin_upn: str = ""


def admin_url_from_graph(g):
    """https://contoso.sharepoint.com -> https://contoso-admin.sharepoint.com"""
    url = g.get("/sites/root", {"$select": "webUrl"}).get("webUrl", "")
    host = url.split("//", 1)[-1].split("/", 1)[0]
    if not host.endswith(".sharepoint.com"):
        return ""
    return f"https://{host.split('.', 1)[0]}-admin.sharepoint.com"


def scan_admin(g, opts, log, ps=psrunner.collect):
    areas, out, ps_data = set(opts.areas), [], {}
    if opts.use_powershell:
        if "Exchange" in areas:
            ps_data["exchange"] = ps("exchange", upn=opts.admin_upn or None, log=log)
        if "Teams" in areas:
            ps_data["teams"] = ps("teams", upn=opts.admin_upn or None, log=log)
        if areas & {"SharePoint", "OneDrive"}:
            try:
                url = admin_url_from_graph(g)
            except Exception as e:
                url = ""
                log(f"[Admin] could not derive SharePoint admin URL: {e}")
            if url:
                ps_data["spo"] = ps("spo", upn=opts.admin_upn or None, adminurl=url, log=log)
    if "Tenant" in areas:
        log("[Admin] Tenant / identity settings")
        out += tenant.admin_checks(g, log)
    if "Teams" in areas:
        log("[Admin] Teams")
        out += teams.admin_checks(g, log, opts.max_teams)
        if "teams" in ps_data:
            out += teams.evaluate_ps(ps_data["teams"])
    if "Exchange" in areas:
        log("[Admin] Exchange Online")
        out += exchange.admin_checks(g, ps_data.get("exchange"), log)
    snap = None
    if areas & {"SharePoint", "OneDrive"}:
        log("[Admin] SharePoint / OneDrive")
        sp_results, snap = sharepoint.admin_checks(g, ps_data.get("spo"), log)
        if "SharePoint" in areas:
            out += sp_results
        if "OneDrive" in areas:
            out += onedrive.admin_checks(g, snap, log)
    return out


def scan_user(g, opts, log):
    areas, out = set(opts.areas), []
    internal = set()
    try:
        internal = exchange.internal_domains(g)
    except Exception as e:
        log(f"[User] could not determine internal domains: {e}")
    if "Teams" in areas:
        log("[User] Teams")
        out += teams.user_checks(g, log)
    if "Exchange" in areas:
        log("[User] Mailbox")
        out += exchange.user_checks(g, log)
    if "SharePoint" in areas:
        log("[User] SharePoint")
        out += sharepoint.user_checks(g, internal, log)
    if "OneDrive" in areas:
        log("[User] OneDrive")
        out += onedrive.user_checks(g, internal, log, opts.max_items)
    return out


def run_scan(admin_graph=None, user_graph=None, opts=None, log=lambda m: None, meta=None, ps=psrunner.collect):
    opts = opts or ScanOptions()
    results = []
    if admin_graph is None and user_graph is None:
        raise ValueError("Sign in as an administrator, an employee, or both before scanning.")
    if admin_graph is not None:
        results += scan_admin(admin_graph, opts, log, ps)
    if user_graph is not None:
        results += scan_user(user_graph, opts, log)
    perspectives = [p for p, g in ((ADMIN, admin_graph), (USER, user_graph)) if g is not None]
    meta = dict(meta or {})
    meta["perspectives"] = ", ".join(perspectives)
    log(f"Scan complete: {len(results)} checks ({meta['perspectives']})")
    return results, meta
