"""Headless runner:  python m365_audit_cli.py --tenant contoso.onmicrosoft.com --client-id <app-id> --admin --user"""
import argparse
import sys

from m365_audit import report
from m365_audit.auth import SignIn
from m365_audit.graph import Graph
from m365_audit.models import AREAS
from m365_audit.scanner import ScanOptions, run_scan


def main():
    ap = argparse.ArgumentParser(description="Read-only Microsoft 365 configuration audit (Teams, Exchange, SharePoint, OneDrive)")
    ap.add_argument("--tenant", required=True, help="tenant domain or ID")
    ap.add_argument("--client-id", required=True, help="your Entra app registration (public client) ID")
    ap.add_argument("--admin", action="store_true", help="sign in as an administrator")
    ap.add_argument("--user", action="store_true", help="sign in as a normal employee")
    ap.add_argument("--areas", default=",".join(AREAS), help="comma separated: " + ",".join(AREAS))
    ap.add_argument("--no-powershell", action="store_true", help="skip Exchange/Teams/SharePoint PowerShell collection")
    ap.add_argument("--browser", action="store_true", help="interactive browser sign-in instead of device code")
    ap.add_argument("--out", default="m365_audit")
    a = ap.parse_args()
    if not (a.admin or a.user):
        ap.error("choose --admin and/or --user")
    areas = tuple(x.strip() for x in a.areas.split(",") if x.strip() in AREAS)
    graphs, names, tid = {}, {}, a.tenant
    for flag, persp in ((a.admin, "Admin"), (a.user, "User")):
        if not flag:
            continue
        print(f"\n== Sign in as {persp.upper()} ==")
        s = SignIn(persp, a.tenant, a.client_id)
        names[persp] = s.login(areas, device_code=not a.browser, show_code=print)
        tid = s.tenant_id or tid
        graphs[persp] = Graph(s.token)
        print(f"Signed in: {names[persp]}")
    res, meta = run_scan(graphs.get("Admin"), graphs.get("User"), ScanOptions(areas, not a.no_powershell, admin_upn=names.get("Admin", "")),
                         log=print, meta={"tenant": tid})
    report.to_html(res, meta, a.out + ".html")
    report.to_csv(res, a.out + ".csv")
    report.to_json(res, meta, a.out + ".json")
    c, score = report.summarize(res)
    print(dict(c), f"score={score}%", "-> reports written to", a.out + ".*")
    return 0


if __name__ == "__main__":
    sys.exit(main())
