"""OneDrive for Business: tenant policy and account hygiene (admin) and my own drive (user)."""
from __future__ import annotations

import csv
import datetime as dt
import io

from .common import guarded
from .models import PASS, FAIL, WARN, INFO, MANUAL, ADMIN, USER, make, short
from .sharepoint import SHARING_LABEL, _sharing_status, scan_sharing, evaluate_scan

AREA = "OneDrive"


def parse_usage_csv(text, today=None, inactive_days=90):
    today = today or dt.date.today()
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    live = [r for r in rows if str(r.get("Is Deleted", "")).lower() != "true"]
    inactive, nearly_full = 0, 0
    for r in live:
        last = (r.get("Last Activity Date") or "").strip()
        try:
            age = (today - dt.date.fromisoformat(last)).days if last else 10 ** 6
        except ValueError:
            age = 10 ** 6
        if age > inactive_days:
            inactive += 1
        try:
            if float(r.get("Storage Allocated (Byte)") or 0) and float(r.get("Storage Used (Byte)") or 0) / float(r["Storage Allocated (Byte)"]) >= 0.9:
                nearly_full += 1
        except (ValueError, ZeroDivisionError):
            pass
    return {"accounts": len(live), "inactive": inactive, "nearly_full": nearly_full, "inactive_days": inactive_days}


def evaluate_admin(spo, usage):
    out = []
    lvl = spo.get("od_sharing")
    if lvl is None:
        out.append(make("OD-A01", ADMIN, AREA, "OneDrive external sharing is not 'Anyone'", MANUAL, "needs SharePoint Online PowerShell", "reviewed",
                        "SharePoint admin center > Policies > Sharing > OneDrive slider, or Get-SPOTenant | fl OneDriveSharingCapability."))
    else:
        out.append(make("OD-A01", ADMIN, AREA, "OneDrive external sharing is not 'Anyone'", _sharing_status(lvl) or WARN, SHARING_LABEL.get(lvl, lvl),
                        "Existing guests or stricter", "Set-SPOTenant -OneDriveSharingCapability ExistingExternalUserSharingOnly"))
    if spo.get("unmanaged_sync_restricted") is not None:
        out.append(make("OD-A02", ADMIN, AREA, "Sync allowed only from managed (domain-joined) devices", PASS if spo["unmanaged_sync_restricted"] else WARN,
                        f"restricted={spo['unmanaged_sync_restricted']}", "True",
                        "SharePoint admin center > Settings > OneDrive sync: 'Allow syncing only on computers joined to specific domains' (or require compliant devices with Conditional Access)."))
    days = spo.get("retention_days")
    if days is not None:
        out.append(make("OD-A03", ADMIN, AREA, "Departed users' OneDrive retained long enough", PASS if int(days) >= 30 else WARN, f"{days} days", ">= 30 days",
                        "OneDrive admin center > Storage: raise 'Days to retain files in OneDrive after a user account is marked for deletion'."))
    if usage is None:
        out.append(make("OD-A04", ADMIN, AREA, "Inactive OneDrive accounts", MANUAL, "usage report not readable (Reports.Read.All)", "reviewed",
                        "Microsoft 365 admin center > Reports > Usage > OneDrive."))
    else:
        out.append(make("OD-A04", ADMIN, AREA, f"OneDrive accounts inactive > {usage['inactive_days']} days", WARN if usage["inactive"] else PASS,
                        f"{usage['inactive']} of {usage['accounts']} accounts", "0 (review leavers)",
                        "Review inactive accounts: unused licences and orphaned data are both risk and cost."))
        out.append(make("OD-A05", ADMIN, AREA, "Accounts nearly out of storage (>= 90%)", WARN if usage["nearly_full"] else PASS,
                        f"{usage['nearly_full']} of {usage['accounts']} accounts", "0", "Ask users to clean up or raise quota for justified cases."))
    return out


def admin_checks(g, spo, log=lambda m: None):
    usage = None
    try:
        usage = parse_usage_csv(g.get_text("/reports/getOneDriveUsageAccountDetail(period='D180')"))
    except Exception as e:  # report not readable (consent / licence): the check becomes MANUAL
        log(f"[Admin/OneDrive] usage report unavailable: {e}")
    return evaluate_admin(spo, usage)


def evaluate_quota(drive):
    q = drive.get("quota") or {}
    state = q.get("state", "normal")
    used, total = q.get("used") or 0, q.get("total") or 0
    pct = f"{100 * used / total:.0f}% used" if total else "n/a"
    return [make("OD-U01", USER, AREA, "My OneDrive has free space", PASS if state == "normal" else (FAIL if state == "exceeded" else WARN),
                 f"{state} ({pct})", "normal", "Delete or archive files, or ask IT for more storage.")]


def user_checks(g, internal, log=lambda m: None, max_items=150):
    def run():
        drive = g.get("/me/drive", {"$select": "id,driveType,quota,webUrl"})
        out = evaluate_quota(drive)
        out += evaluate_scan(scan_sharing(g, "/me/drive", internal, max_items=max_items), AREA, "OD-U", USER, "my OneDrive")
        return out
    return guarded("OD-U01", USER, AREA, "My OneDrive", run, log, "Files.Read")
