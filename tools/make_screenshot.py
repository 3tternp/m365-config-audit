"""Render the GUI with DEMO data (canned fake tenant, not a real environment) -> docs/screenshot*.png.
Requires Pillow and a desktop session."""
import ctypes
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    pass

from PIL import ImageGrab  # noqa: E402
import test_checks as t  # noqa: E402
import m365_audit.exchange as ex  # noqa: E402
from m365_audit import scanner  # noqa: E402
from m365_audit.gui import App  # noqa: E402

ex.default_lookup = t.lookup_factory({"contoso.com": ["v=spf1 include:spf.protection.outlook.com ~all"], "_dmarc.contoso.com": ["v=DMARC1; p=none"]})
admin_routes = dict(t.TEAM_ROUTES, **{
    "/policies/authorizationPolicy": {"value": [{"allowInvitesFrom": "everyone", "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3"}]},
    "/identity/conditionalAccess/policies": [], "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
    "/directoryRoles/roleTemplateId=62e90394-69f5-4237-9190-012177145e10/members": [{}, {}, {}],
    "/domains": [{"id": "contoso.com", "isVerified": True}], "/admin/sharepoint/settings": t.GRAPH_SPO,
    "/sites/root": {"webUrl": "https://contoso.sharepoint.com"},
    "/reports/getOneDriveUsageAccountDetail(period='D180')": ("Report Refresh Date,Site URL,Is Deleted,Last Activity Date,Storage Used (Byte),Storage Allocated (Byte)\n"
                                                              "2026-11-01,a,False,2026-11-20,95,100\n2026-11-01,b,False,2025-01-01,10,100\n")})
user_routes = dict(t.DRIVE, **{"/me": {"userPrincipalName": "alex@contoso.com"}, "/organization": [{"verifiedDomains": [{"name": "contoso.com"}]}],
                               "/me/joinedTeams": [{"id": "t1", "displayName": "Finance"}], "/teams/t1": {"visibility": "public"},
                               "/teams/t1/members": [{"roles": ["owner"]}, {"roles": ["guest"]}],
                               "/me/mailFolders/inbox/messageRules": [{"displayName": "fwd", "isEnabled": True, "actions": {"forwardTo": [{"emailAddress": {"address": "me@gmail.com"}}]}}],
                               "/me/mailboxSettings": {"automaticRepliesSetting": {"status": "alwaysEnabled", "externalAudience": "all"}},
                               "/me/calendar/calendarPermissions": [], "/sites": []})
res, meta = scanner.run_scan(t.FakeGraph(admin_routes), t.FakeGraph(user_routes), scanner.ScanOptions(),
                             ps=lambda s, **k: {"exchange": t.EXO, "spo": t.PS_SPO, "teams": {}}[s], meta={"tenant": "demo (made-up data)"})

app = App()
app.geometry("1400x760+30+20")
app.tenant.insert(0, "contoso.onmicrosoft.com")
app.chip["Admin"].configure(text="admin@contoso.com", text_color="#30a46c")
app.chip["User"].configure(text="alex@contoso.com", text_color="#30a46c")
app.load_results(res, meta)
app.tree.selection_set(app.tree.get_children()[0])
app._detail()
app.update()
app.after(900, app.quit)
app.mainloop()
x, y, w, h = app.winfo_rootx(), app.winfo_rooty(), app.winfo_width(), app.winfo_height()
out = ROOT / "docs"
out.mkdir(exist_ok=True)
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_dark.png")
app.f_persp.set("User")
app._refresh()
app.mode_menu.set("Light")
app._set_mode("Light")
app.update()
app.after(900, app.quit)
app.mainloop()
ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out / "screenshot_light.png")
print("saved", sorted(p.name for p in out.glob("screenshot*")), len(res), "findings")
