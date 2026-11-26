"""Offline tests: every check runs against canned Graph / PowerShell data (no tenant, no network).

Run:  python tests/test_checks.py
"""
import datetime as dt
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from m365_audit import teams, tenant, exchange, sharepoint, onedrive, psrunner, scanner, report, gui_model  # noqa: E402
from m365_audit.graph import Graph, GraphError  # noqa: E402
from m365_audit.models import AREAS  # noqa: E402


class FakeGraph:
    def __init__(self, routes):
        self.routes = routes

    def _r(self, path):
        if path in self.routes:
            v = self.routes[path]
            if isinstance(v, Exception):
                raise v
            return v
        raise GraphError(404, "NotFound", path)

    def get(self, path, params=None):
        return self._r(path)

    def get_all(self, path, params=None, limit=2000):
        v = self._r(path)
        return (v["value"] if isinstance(v, dict) and "value" in v else v)[:limit]

    def get_text(self, path):
        return self._r(path)


def by_id(res):
    return {r.check_id: r for r in res}


# ---------------------------------------------------------------- Teams
TEAM_ROUTES = {
    "/groupSettings": {"value": [{"displayName": "Group.Unified", "values": [{"name": "EnableGroupCreation", "value": "true"},
                                                                          {"name": "AllowGuestsToBeGroupOwner", "value": "true"}]}]},
    "/teamwork/teamsAppSettings": {"isChatResourceSpecificConsentEnabled": True},
    "/groups": [{"id": "t1", "displayName": "Finance", "visibility": "Public", "assignedLabels": []},
                {"id": "t2", "displayName": "Board", "visibility": "Private", "assignedLabels": [{"labelId": "x"}]}],
    "/groups/t1/owners": [], "/groups/t2/owners": [{"id": "u"}],
    "/groups/t1/members/microsoft.graph.user": [{"userType": "Guest"}, {"userType": "Member"}],
    "/groups/t2/members/microsoft.graph.user": [{"userType": "Member"}],
    "/teams/t1": {"guestSettings": {"allowCreateUpdateChannels": True}}, "/teams/t2": {"guestSettings": {}},
}


def test_teams_admin():
    r = by_id(teams.admin_checks(FakeGraph(TEAM_ROUTES)))
    assert r["TEAMS-A01"].status == "WARN" and r["TEAMS-A02"].status == "WARN" and r["TEAMS-A03"].status == "WARN"
    assert r["TEAMS-A04"].status == "FAIL" and "Finance" in r["TEAMS-A04"].actual          # ownerless team
    assert r["TEAMS-A05"].status == "WARN" and "Board" in r["TEAMS-A05"].actual            # single owner
    assert r["TEAMS-A06"].status == "INFO" and r["TEAMS-A07"].status == "INFO"
    assert r["TEAMS-A08"].status == "WARN" and r["TEAMS-A09"].status == "WARN"


def test_teams_access_denied_is_reported_not_crashed():
    routes = dict(TEAM_ROUTES, **{"/groupSettings": GraphError(403, "Forbidden", "no")})
    r = by_id(teams.admin_checks(FakeGraph(routes)))
    assert r["TEAMS-A01"].status == "WARN" and "denied" in r["TEAMS-A01"].actual
    assert "TEAMS-A04" in r                                                                 # the rest still ran


def test_teams_ps():
    data = {"Federation": {"data": [{"AllowFederatedUsers": True, "AllowPublicUsers": True}], "error": None},
            "MeetingPolicy": {"data": [{"AllowAnonymousUsersToJoinMeeting": True, "AutoAdmittedUsers": "Everyone"}], "error": None},
            "ClientConfig": {"data": [{"AllowDropBox": True}], "error": None}}
    r = by_id(teams.evaluate_ps(data))
    assert r["TEAMS-A10"].status == "WARN" and r["TEAMS-A12"].status == "WARN" and r["TEAMS-A13"].status == "FAIL"
    assert r["TEAMS-A15"].status == "WARN"
    assert by_id(teams.evaluate_ps({"Federation": {"data": None, "error": "module missing"}}))["TEAMS-A10"].status == "MANUAL"


def test_teams_user():
    g = FakeGraph({"/me/joinedTeams": [{"id": "t1", "displayName": "Finance"}], "/teams/t1": {"visibility": "public"},
                   "/teams/t1/members": [{"roles": ["owner"]}, {"roles": ["guest"]}]})
    r = by_id(teams.user_checks(g))
    assert r["TEAMS-U02"].status == "INFO" and r["TEAMS-U03"].status == "INFO" and r["TEAMS-U04"].status == "WARN"
    denied = by_id(teams.user_checks(FakeGraph({"/me/joinedTeams": GraphError(403, "Forbidden")})))
    assert denied["TEAMS-U01"].status == "WARN"


# ---------------------------------------------------------------- Tenant
def test_tenant():
    assert by_id(tenant.evaluate_authz({"allowInvitesFrom": "everyone", "guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970",
                                        "defaultUserRolePermissions": {"allowedToCreateApps": True}}))["TEN-A01"].status == "FAIL"
    ca = [{"state": "enabled", "displayName": "MFA", "grantControls": {"builtInControls": ["mfa"]},
           "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]}},
          {"state": "enabled", "displayName": "NoLegacy", "grantControls": {"builtInControls": ["block"]},
           "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]},
                          "clientAppTypes": ["exchangeActiveSync", "other"]}}]
    r = by_id(tenant.evaluate_ca(ca, False))
    assert r["TEN-A04"].status == "PASS" and r["TEN-A05"].status == "PASS"
    r = by_id(tenant.evaluate_ca([], False))
    assert r["TEN-A04"].status == "FAIL" and by_id(tenant.evaluate_ca([], True))["TEN-A04"].status == "PASS"
    assert tenant.evaluate_global_admins(3)[0].status == "PASS" and tenant.evaluate_global_admins(9)[0].status == "FAIL"
    assert tenant.evaluate_global_admins(1)[0].status == "WARN"


# -------------------------------------------------------------- Exchange
def lookup_factory(records):
    def lookup(name, rtype="TXT"):
        if name in records:
            return records[name]
        raise LookupError(name)
    return lookup


def test_dns():
    good = lookup_factory({"a.com": ["v=spf1 include:spf.protection.outlook.com -all"], "_dmarc.a.com": ["v=DMARC1; p=reject"]})
    r = by_id(exchange.evaluate_domain_dns("a.com", good))
    assert r["EXO-A20"].status == "PASS" and r["EXO-A21"].status == "PASS"
    weak = lookup_factory({"b.com": ["v=spf1 ~all"], "_dmarc.b.com": ["v=DMARC1; p=none"]})
    r = by_id(exchange.evaluate_domain_dns("b.com", weak))
    assert r["EXO-A20"].status == "WARN" and r["EXO-A21"].status == "WARN"
    r = by_id(exchange.evaluate_domain_dns("c.com", lookup_factory({})))
    assert r["EXO-A20"].status == "FAIL" and r["EXO-A21"].status == "FAIL"
    open_ = lookup_factory({"d.com": ["v=spf1 +all"]})
    assert by_id(exchange.evaluate_domain_dns("d.com", open_))["EXO-A20"].status == "FAIL"


EXO = {
    "OutboundSpam": {"data": [{"Name": "Default", "AutoForwardingMode": "On"}], "error": None},
    "RemoteDomain": {"data": [{"Name": "Default", "DomainName": "*", "AutoForwardEnabled": True}], "error": None},
    "TransportRules": {"data": [{"Name": "Allowlist", "State": "Enabled", "SetSCL": -1},
                                {"Name": "Copy", "State": "Enabled", "BlindCopyTo": "x@evil.com"}], "error": None},
    "TransportConfig": {"data": [{"SmtpClientAuthenticationDisabled": False}], "error": None},
    "Forwarding": {"data": [{"UserPrincipalName": "a@contoso.com", "ForwardingSmtpAddress": "smtp:a@gmail.com"}], "error": None},
    "AcceptedDomains": {"data": [{"DomainName": "contoso.com"}], "error": None},
    "OrganizationConfig": {"data": [{"OAuth2ClientProfileEnabled": True, "AuditDisabled": False, "CustomerLockboxEnabled": False}], "error": None},
    "AuditConfig": {"data": [{"UnifiedAuditLogIngestionEnabled": False}], "error": None},
    "AntiPhish": {"data": [{"Name": "p", "Enabled": True, "EnableSpoofIntelligence": True, "EnableMailboxIntelligence": False}], "error": None},
    "SafeLinks": {"data": [], "error": None}, "SafeAttachments": {"data": [], "error": None},
    "Malware": {"data": [{"Name": "Default", "EnableFileFilter": False}], "error": None},
    "Dkim": {"data": {"Domain": "contoso.com", "Enabled": False}, "error": None},      # single object (PowerShell quirk)
    "OwaPolicy": {"data": [{"Name": "Default", "AdditionalStorageProvidersAvailable": True}], "error": None},
}


def test_exchange_ps():
    r = by_id(exchange.evaluate_ps(EXO))
    assert r["EXO-A01"].status == "FAIL" and r["EXO-A02"].status == "FAIL" and r["EXO-A03"].status == "FAIL"
    assert r["EXO-A04"].status == "FAIL" and "gmail" in r["EXO-A04"].actual
    assert r["EXO-A05"].status == "WARN" and r["EXO-A06"].status == "WARN"
    assert r["EXO-A07"].status == "PASS" and r["EXO-A09"].status == "INFO" and r["EXO-A10"].status == "FAIL"
    assert r["EXO-A11"].status == "WARN" and r["EXO-A12"].status == "INFO" and r["EXO-A13"].status == "WARN"
    assert r["EXO-A14"].status == "FAIL" and r["EXO-A15"].status == "WARN"
    assert by_id(exchange.evaluate_ps({"OutboundSpam": {"data": None, "error": "x"}}))["EXO-A01"].status == "MANUAL"


def test_exchange_user():
    internal = {"contoso.com"}
    rules = [{"displayName": "fwd", "isEnabled": True, "actions": {"forwardTo": [{"emailAddress": {"address": "me@gmail.com"}}]}},
             {"displayName": "hide", "isEnabled": True, "actions": {"delete": True}},
             {"displayName": "internal", "isEnabled": True, "actions": {"forwardTo": [{"emailAddress": {"address": "b@contoso.com"}}]}},
             {"displayName": "off", "isEnabled": False, "actions": {"redirectTo": [{"emailAddress": {"address": "x@evil.com"}}]}}]
    r = by_id(exchange.evaluate_rules(rules, internal))
    assert r["EXO-U01"].status == "FAIL" and "gmail" in r["EXO-U01"].actual and "evil" not in r["EXO-U01"].actual
    assert r["EXO-U02"].status == "WARN"
    assert exchange.evaluate_autoreply({"automaticRepliesSetting": {"status": "alwaysEnabled", "externalAudience": "all"}})[0].status == "WARN"
    assert exchange.evaluate_autoreply({"automaticRepliesSetting": {"status": "disabled"}})[0].status == "PASS"
    cal = [{"emailAddress": {"address": "p@partner.com"}, "role": "read"}, {"emailAddress": {"address": "c@contoso.com"}, "role": "write"}]
    assert exchange.evaluate_calendar(cal, internal)[0].status == "WARN"
    g = FakeGraph({"/me": {"userPrincipalName": "u@contoso.com"}, "/organization": [{"verifiedDomains": [{"name": "contoso.com"}]}],
                   "/me/mailFolders/inbox/messageRules": rules, "/me/mailboxSettings": {}, "/me/calendar/calendarPermissions": cal})
    assert {"EXO-U01", "EXO-U02", "EXO-U03", "EXO-U04"} <= set(by_id(exchange.user_checks(g)))


# ---------------------------------------------------------- SharePoint / OneDrive
GRAPH_SPO = {"sharingCapability": "externalUserAndGuestSharing", "isResharingByExternalUsersEnabled": True,
             "isLegacyAuthProtocolsEnabled": True, "sharingDomainRestrictionMode": "none", "idleSessionSignOut": {"isEnabled": False},
             "isSiteCreationEnabled": True, "isUnmanagedSyncAppForTenantRestricted": False, "deletedUserPersonalSiteRetentionPeriodInDays": 10}
PS_SPO = {"Tenant": {"data": [{"OneDriveSharingCapability": "ExternalUserAndGuestSharing", "DefaultSharingLinkType": "AnonymousAccess",
                               "DefaultLinkPermission": "Edit", "RequireAnonymousLinksExpireInDays": -1, "ExternalUserExpirationRequired": False,
                               "EmailAttestationRequired": False, "DisallowInfectedFileDownload": False, "ShowEveryoneClaim": True}], "error": None},
          "Sites": {"data": [{"Url": "https://x/sites/a", "SharingCapability": "ExternalUserAndGuestSharing"},
                             {"Url": "https://x/sites/b", "SharingCapability": "Disabled"}], "error": None}}


def test_spo_admin():
    snap = sharepoint.spo_snapshot(GRAPH_SPO, PS_SPO)
    r = by_id(sharepoint.evaluate_spo(snap))
    assert r["SP-A01"].status == "FAIL" and r["SP-A02"].status == "FAIL" and r["SP-A03"].status == "FAIL"
    assert r["SP-A04"].status == "WARN" and r["SP-A05"].status == "WARN" and r["SP-A06"].status == "FAIL"
    assert r["SP-A07"].status == "WARN" and r["SP-A08"].status == "FAIL" and r["SP-A09"].status == "WARN"
    assert r["SP-A11"].status == "WARN" and r["SP-A12"].status == "FAIL" and r["SP-A14"].status == "WARN" and "1 of 2" in r["SP-A14"].actual
    assert "SP-A00" not in r
    graph_only = by_id(sharepoint.evaluate_spo(sharepoint.spo_snapshot(GRAPH_SPO, None)))
    assert graph_only["SP-A00"].status == "MANUAL" and "SP-A06" not in graph_only
    strict = by_id(sharepoint.evaluate_spo(sharepoint.spo_snapshot({"sharingCapability": "disabled"}, None)))
    assert strict["SP-A01"].status == "PASS"
    assert by_id(sharepoint.evaluate_spo(sharepoint.spo_snapshot({}, None)))["SP-A01"].status == "MANUAL"


def test_onedrive_admin():
    snap = sharepoint.spo_snapshot(GRAPH_SPO, PS_SPO)
    csv_text = ("﻿Report Refresh Date,Site URL,Is Deleted,Last Activity Date,Storage Used (Byte),Storage Allocated (Byte)\n"
                "2026-11-01,a,False,2026-11-20,95,100\n2026-11-01,b,False,2025-01-01,10,100\n2026-11-01,c,True,2020-01-01,1,100\n")
    usage = onedrive.parse_usage_csv(csv_text, today=dt.date(2026, 11, 26))
    assert usage == {"accounts": 2, "inactive": 1, "nearly_full": 1, "inactive_days": 90}
    r = by_id(onedrive.evaluate_admin(snap, usage))
    assert r["OD-A01"].status == "FAIL" and r["OD-A02"].status == "WARN" and r["OD-A03"].status == "WARN"
    assert r["OD-A04"].status == "WARN" and r["OD-A05"].status == "WARN"
    assert by_id(onedrive.evaluate_admin(snap, None))["OD-A04"].status == "MANUAL"


DRIVE = {
    "/me/drive/root/children": [{"id": "f1", "name": "Docs", "folder": {}, "shared": {}}, {"id": "i1", "name": "plan.docx", "file": {}, "shared": {"scope": "anonymous"}},
                                {"id": "i2", "name": "private.txt", "file": {}}],
    "/me/drive/items/f1/children": [{"id": "i3", "name": "budget.xlsx", "file": {}, "shared": {"scope": "users"}}],
    "/me/drive/items/f1/permissions": [],
    "/me/drive/items/i1/permissions": [{"link": {"scope": "anonymous", "type": "edit"}}],
    "/me/drive/items/i3/permissions": [{"grantedToV2": {"user": {"email": "ext@partner.com"}}}, {"link": {"scope": "organization", "type": "edit"}}],
    "/me/drive": {"quota": {"state": "nearing", "used": 90, "total": 100}},
}


def test_sharing_scan_and_user_onedrive():
    scan = sharepoint.scan_sharing(FakeGraph(DRIVE), "/me/drive", {"contoso.com"})
    assert scan["scanned"] == 4 and scan["anon_edit"] == ["plan.docx"] and scan["external"] == ["budget.xlsx -> ext@partner.com"]
    assert scan["org_edit"] == ["budget.xlsx"]
    r = by_id(onedrive.user_checks(FakeGraph(DRIVE), {"contoso.com"}))
    assert r["OD-U01"].status == "WARN" and r["OD-U-01"].status == "FAIL" and r["OD-U-02"].status == "WARN" and r["OD-U-03"].status == "INFO"
    # the item cap bounds the number of API calls
    capped = sharepoint.scan_sharing(FakeGraph(DRIVE), "/me/drive", set(), max_items=2)
    assert capped["scanned"] == 2


def test_sharepoint_user():
    routes = {"/sites": [{"id": "s1", "displayName": "HR"}], "/sites/s1/drive/root/children": [{"id": "d1", "name": "cv.pdf", "file": {}}],
              "/sites/s1/drive/items/d1/permissions": [{"link": {"scope": "anonymous", "type": "view"}}]}
    r = by_id(sharepoint.user_checks(FakeGraph(routes), {"contoso.com"}))
    assert r["SP-U00"].status == "INFO" and r["SP-U-01"].status == "WARN" and "HR/cv.pdf" in r["SP-U-01"].actual


# ------------------------------------------------------- PowerShell runner
def test_ps_scripts_are_read_only():
    for svc, cfg in psrunner.SERVICES.items():
        for name, cmd in cfg["commands"].items():
            assert cmd.split()[0].startswith("Get-"), (svc, name, cmd)       # only Get-* cmdlets
            for bad in ("Set-", "Remove-", "New-", "Enable-", "Disable-", "Add-", "Invoke-"):
                assert bad not in cmd, (svc, name, bad)
        script = psrunner.build_script(svc, upn="a@contoso.com", adminurl="https://contoso-admin.sharepoint.com")
        assert psrunner.MARK in script and cfg["module"] in script


def test_ps_script_rejects_injection():
    evil = "a@b.com'; Remove-Item C:/tmp -Recurse; '"
    script = psrunner.build_script("exchange", upn=evil)
    assert "Remove-Item" not in script and "-UserPrincipalName" not in script       # malformed hint is dropped
    assert "-UserPrincipalName 'a@contoso.com'" in psrunner.build_script("exchange", upn="a@contoso.com")
    for bad in ("https://x.sharepoint.com'; calc; '", "https://evil.com", "", None):
        try:
            psrunner.build_script("spo", adminurl=bad)
            assert False, bad
        except ValueError:
            pass
    real = psrunner.find_exe
    psrunner.find_exe = lambda candidates: "powershell-stub"      # CI runners may have no PowerShell; the check must not depend on it
    try:
        out = psrunner.collect("spo", adminurl="https://evil.com", runner=lambda *a, **k: None)
    finally:
        psrunner.find_exe = real
    assert all(v["data"] is None and "invalid" in v["error"] for v in out.values())


def test_ps_collect_with_fake_runner():
    payload = {"Tenant": {"data": [{"SharingCapability": "Disabled"}], "error": None}}

    class P:
        stdout = "banner\n" + psrunner.MARK + "\n" + json.dumps(payload)
    out = psrunner.collect("spo", adminurl="https://x-admin.sharepoint.com", runner=lambda *a, **k: P())
    if psrunner.find_exe(("powershell",)):
        assert out["Tenant"]["data"][0]["SharingCapability"] == "Disabled"

    class Bad:
        stdout = "no marker"
    out = psrunner.collect("teams", runner=lambda *a, **k: Bad())
    assert all(v["data"] is None and v["error"] for v in out.values())


# -------------------------------------------------------- Graph client + scanner
class FakeResp:
    def __init__(self, status, body, headers=None):
        self.status_code, self._b, self.headers, self.content, self.text = status, body, headers or {}, b"x", json.dumps(body)

    def json(self):
        return self._b


class FakeHttp:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), 0

    def get(self, url, **kw):
        self.calls += 1
        assert kw["headers"]["Authorization"] == "Bearer tok"
        return self.responses.pop(0)


def test_graph_client_paging_retry_errors():
    http = FakeHttp([FakeResp(429, {}, {"Retry-After": "1"}), FakeResp(200, {"value": [1, 2], "@odata.nextLink": "https://next"}),
                     FakeResp(200, {"value": [3]})])
    g = Graph(lambda: "tok", session=http, sleep=lambda s: None)
    assert g.get_all("/x") == [1, 2, 3] and http.calls == 3
    g = Graph(lambda: "tok", session=FakeHttp([FakeResp(403, {"error": {"code": "Forbidden", "message": "nope"}})]))
    try:
        g.get("/y")
        assert False
    except GraphError as e:
        assert e.denied and e.code == "Forbidden"


def test_scanner_end_to_end():
    admin_routes = dict(TEAM_ROUTES, **{
        "/policies/authorizationPolicy": {"value": [{"allowInvitesFrom": "everyone", "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3"}]},
        "/identity/conditionalAccess/policies": [], "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
        "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [{}, {}, {}],
        "/domains": [{"id": "contoso.com", "isVerified": True}, {"id": "contoso.onmicrosoft.com", "isVerified": True}],
        "/admin/sharepoint/settings": GRAPH_SPO, "/sites/root": {"webUrl": "https://contoso.sharepoint.com"},
        "/reports/getOneDriveUsageAccountDetail(period='D180')": GraphError(403, "Forbidden")})
    calls = []

    def fake_ps(service, upn=None, adminurl=None, log=None):
        calls.append(service)
        return {"exchange": EXO, "spo": PS_SPO, "teams": {}}[service]
    user_routes = dict(DRIVE, **{"/me": {"userPrincipalName": "u@contoso.com"}, "/organization": GraphError(403, "Forbidden"),
                                 "/me/joinedTeams": [], "/me/mailFolders/inbox/messageRules": [], "/me/mailboxSettings": {},
                                 "/me/calendar/calendarPermissions": [], "/sites": []})
    import m365_audit.exchange as ex
    ex.default_lookup = lookup_factory({})
    res, meta = scanner.run_scan(FakeGraph(admin_routes), FakeGraph(user_routes), scanner.ScanOptions(), ps=fake_ps, meta={"tenant": "contoso"})
    assert sorted(calls) == ["exchange", "spo", "teams"]
    assert meta["perspectives"] == "Admin, User"
    persp = {r.perspective for r in res}
    areas = {r.area for r in res}
    assert persp == {"Admin", "User"} and areas == set(AREAS), (persp, areas)
    ids = {r.check_id for r in res}
    assert {"TEN-A04", "TEAMS-A04", "EXO-A01", "SP-A01", "OD-A01", "OD-A04", "TEAMS-U01", "EXO-U01", "SP-U00", "OD-U-01"} <= ids
    assert not any(r.status == "ERROR" for r in res), [r for r in res if r.status == "ERROR"]
    # admin-only and user-only scans work
    assert {r.perspective for r in scanner.run_scan(FakeGraph(admin_routes), None, scanner.ScanOptions(areas=("Tenant",)), ps=fake_ps)[0]} == {"Admin"}
    try:
        scanner.run_scan(None, None)
        assert False
    except ValueError:
        pass
    # reports escape tenant data
    evil = res[0]
    evil.actual = "<script>alert(1)</script>"
    import tempfile
    d = tempfile.mkdtemp()
    report.to_html(res, meta, os.path.join(d, "r.html"))
    report.to_csv(res, os.path.join(d, "r.csv"))
    report.to_json(res, meta, os.path.join(d, "r.json"))
    page = open(os.path.join(d, "r.html"), encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    # GUI model
    assert gui_model.filter_results(res, perspective="User", area="OneDrive")
    assert all(r.perspective == "User" for r in gui_model.filter_results(res, perspective="User"))
    rows = gui_model.by_area(res)
    assert {(x["area"], x["perspective"]) for x in rows} >= {("Teams", "Admin"), ("OneDrive", "User")}
    c, score = gui_model.summary(res)
    assert 0 <= score <= 100 and sum(c.values()) == len(res)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
    print("OK - all offline tests passed")
