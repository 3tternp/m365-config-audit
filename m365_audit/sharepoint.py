"""SharePoint Online: tenant sharing settings (admin) and what an employee's sites expose (user).

Admin data is merged from Microsoft Graph (/admin/sharepoint/settings) and, when available, the
SharePoint Online PowerShell module (Get-SPOTenant / Get-SPOSite) for settings Graph does not expose.
"""
from __future__ import annotations

from .common import guarded, aslist, domain_of
from .models import PASS, FAIL, WARN, INFO, MANUAL, ADMIN, USER, make, short

AREA = "SharePoint"


def _l(v):
    return None if v is None else str(v).replace("_", "").lower()


def spo_snapshot(graph_settings, ps_data):
    """Normalise Graph (camelCase) and PowerShell (PascalCase) tenant settings into one dict; unknown = None."""
    gs = graph_settings or {}
    t = {}
    if ps_data and not (ps_data.get("Tenant") or {}).get("error"):
        rows = aslist((ps_data.get("Tenant") or {}).get("data"))
        t = rows[0] if rows else {}
    pick = lambda g_key, p_key: gs.get(g_key) if gs.get(g_key) is not None else t.get(p_key)
    prevent = t.get("PreventExternalUsersFromResharing")
    sites = aslist((ps_data or {}).get("Sites", {}).get("data")) if ps_data and not (ps_data.get("Sites") or {}).get("error") else None
    return {
        "sharing": _l(pick("sharingCapability", "SharingCapability")),
        "od_sharing": _l(t.get("OneDriveSharingCapability")),
        "resharing": gs.get("isResharingByExternalUsersEnabled") if gs.get("isResharingByExternalUsersEnabled") is not None
        else (None if prevent is None else not prevent),
        "legacy_auth": pick("isLegacyAuthProtocolsEnabled", "LegacyAuthProtocolsEnabled"),
        "domain_mode": _l(pick("sharingDomainRestrictionMode", "SharingDomainRestrictionMode")),
        "idle": gs.get("idleSessionSignOut"),
        "site_creation": gs.get("isSiteCreationEnabled"),
        "unmanaged_sync_restricted": gs.get("isUnmanagedSyncAppForTenantRestricted"),
        "retention_days": pick("deletedUserPersonalSiteRetentionPeriodInDays", "OrphanedPersonalSitesRetentionPeriod"),
        "link_type": _l(t.get("DefaultSharingLinkType")), "link_perm": _l(t.get("DefaultLinkPermission")),
        "anon_expiry": t.get("RequireAnonymousLinksExpireInDays"), "guest_expiry_required": t.get("ExternalUserExpirationRequired"),
        "email_attestation": t.get("EmailAttestationRequired"), "infected_blocked": t.get("DisallowInfectedFileDownload"),
        "show_everyone": t.get("ShowEveryoneClaim"), "show_everyone_except": t.get("ShowEveryoneExceptExternalUsersClaim"),
        "sites": sites, "ps_ok": bool(t), "graph_ok": bool(gs),
    }


def _sharing_status(level):
    return {"disabled": PASS, "existingexternalusersharingonly": PASS, "externalusersharingonly": WARN,
            "externaluserandguestsharing": FAIL}.get(level)


SHARING_LABEL = {"disabled": "Only people in your organization", "existingexternalusersharingonly": "Existing guests only",
                 "externalusersharingonly": "New and existing guests", "externaluserandguestsharing": "Anyone (anonymous links)"}


def evaluate_spo(s):
    out = []

    def add(cid, title, status, actual, expected, fix):
        out.append(make(cid, ADMIN, AREA, title, status, actual, expected, fix))

    def unknown(cid, title, how):
        out.append(make(cid, ADMIN, AREA, title, MANUAL, "not available (Graph denied / PowerShell not run)", "reviewed", how))

    lvl = s["sharing"]
    if lvl is None:
        unknown("SP-A01", "External sharing level is not 'Anyone'", "SharePoint admin center > Policies > Sharing.")
    else:
        add("SP-A01", "External sharing level is not 'Anyone'", _sharing_status(lvl) or WARN, SHARING_LABEL.get(lvl, lvl), "Existing guests or stricter",
            "SharePoint admin center > Policies > Sharing: lower the external sharing slider (Set-SPOTenant -SharingCapability ExistingExternalUserSharingOnly).")
    if s["resharing"] is not None:
        add("SP-A02", "External users cannot reshare content", FAIL if s["resharing"] else PASS, f"external resharing={s['resharing']}", "False",
            "Set-SPOTenant -PreventExternalUsersFromResharing $true")
    if s["legacy_auth"] is not None:
        add("SP-A03", "Legacy authentication protocols disabled", FAIL if s["legacy_auth"] else PASS, f"legacy auth={s['legacy_auth']}", "False",
            "Set-SPOTenant -LegacyAuthProtocolsEnabled $false")
    ext_on = lvl not in (None, "disabled")
    if s["domain_mode"] is not None and ext_on:
        add("SP-A04", "External sharing limited to allowed/blocked domains", WARN if s["domain_mode"] == "none" else PASS,
            f"domain restriction={s['domain_mode']}", "allowList (or blockList)", "Sharing > More external sharing settings > Limit external sharing by domain.")
    idle = s["idle"] or {}
    if s["idle"] is not None:
        add("SP-A05", "Idle session sign-out enabled", PASS if idle.get("isEnabled") else WARN, f"enabled={idle.get('isEnabled')}", "enabled",
            "SharePoint admin center > Policies > Access control > Idle session sign-out.")
    if s["link_type"] is not None:
        add("SP-A06", "Default sharing link is not 'Anyone'", FAIL if s["link_type"] == "anonymousaccess" else (PASS if s["link_type"] in ("direct", "internal") else WARN),
            f"default link={s['link_type']}", "Specific people (Direct) or Internal", "Set-SPOTenant -DefaultSharingLinkType Direct")
    if s["link_perm"] is not None:
        add("SP-A07", "Default link permission is View", WARN if s["link_perm"] == "edit" else PASS, f"default permission={s['link_perm']}", "View",
            "Set-SPOTenant -DefaultLinkPermission View")
    if lvl == "externaluserandguestsharing":
        exp = s["anon_expiry"]
        add("SP-A08", "Anonymous links expire within 30 days", PASS if (isinstance(exp, int) and 0 < exp <= 30) else FAIL,
            f"expiry days={exp}", "<= 30", "Set-SPOTenant -RequireAnonymousLinksExpireInDays 30")
    if s["guest_expiry_required"] is not None and ext_on:
        add("SP-A09", "Guest access expires automatically", PASS if s["guest_expiry_required"] else WARN, f"required={s['guest_expiry_required']}", "True",
            "Set-SPOTenant -ExternalUserExpirationRequired $true -ExternalUserExpireInDays 60")
    if s["email_attestation"] is not None and ext_on:
        add("SP-A10", "Guests must re-verify by e-mail code", PASS if s["email_attestation"] else WARN, f"required={s['email_attestation']}", "True",
            "Set-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 30")
    if s["infected_blocked"] is not None:
        add("SP-A11", "Download of infected files blocked", PASS if s["infected_blocked"] else WARN, f"blocked={s['infected_blocked']}", "True",
            "Set-SPOTenant -DisallowInfectedFileDownload $true")
    if s["show_everyone"] is not None:
        bad = bool(s["show_everyone"])
        add("SP-A12", "'Everyone' claim hidden from people picker", FAIL if bad else (WARN if s["show_everyone_except"] else PASS),
            f"Everyone={s['show_everyone']}, Everyone except external={s['show_everyone_except']}", "False",
            "Set-SPOTenant -ShowEveryoneClaim $false -ShowEveryoneExceptExternalUsersClaim $false (prevents oversharing to the whole company).")
    if s["site_creation"] is not None:
        add("SP-A13", "Users can create SharePoint sites", INFO if s["site_creation"] else PASS, f"site creation={s['site_creation']}", "reviewed",
            "Consider limiting self-service site creation (governance).")
    if s["sites"] is not None:
        anyone = [x.get("Url") for x in s["sites"] if _l(x.get("SharingCapability")) == "externaluserandguestsharing"]
        add("SP-A14", "Sites allowing 'Anyone' links", WARN if anyone else PASS, f"{len(anyone)} of {len(s['sites'])}: " + short(anyone) if anyone else "none", "none unless justified",
            "Set-SPOSite -Identity <url> -SharingCapability ExistingExternalUserSharingOnly")
    if not s["ps_ok"]:
        out.append(make("SP-A00", ADMIN, AREA, "Settings only available through SharePoint Online PowerShell", MANUAL,
                        "PowerShell data not collected: default link type, anonymous expiry, guest expiry, e-mail attestation, Everyone claim, per-site sharing",
                        "reviewed", "Enable the PowerShell option and install Microsoft.Online.SharePoint.PowerShell, or check these in the SharePoint admin center."))
    return out


def admin_checks(g, ps_data=None, log=lambda m: None):
    graph = {}

    def fetch():
        graph.update(g.get("/admin/sharepoint/settings"))
        return []
    res = guarded("SP-A00", ADMIN, AREA, "SharePoint tenant settings (Graph)", fetch, log, "SharePointTenantSettings.Read.All")
    snap = spo_snapshot(graph, ps_data)
    return res + evaluate_spo(snap), snap


# ------------------------------------------------------------------------- user: sharing exposure
def classify_permissions(perms, internal):
    """Return (anon_view, anon_edit, org_edit, externals) booleans/lists for one item's permissions."""
    anon_view = anon_edit = org_edit = False
    ext = []
    for p in perms:
        link = p.get("link") or {}
        scope, typ = link.get("scope"), link.get("type")
        if scope == "anonymous":
            if typ == "edit":
                anon_edit = True
            else:
                anon_view = True
        elif scope == "organization" and typ == "edit":
            org_edit = True
        identities = [p.get("grantedToV2")] + list(p.get("grantedToIdentitiesV2") or [])
        for ident in identities:
            u = (ident or {}).get("user") or (ident or {}).get("siteUser") or {}
            mail = u.get("email") or u.get("loginName", "")
            if "@" in mail and domain_of(mail.split("|")[-1]) not in internal:
                ext.append(mail.split("|")[-1])
    return anon_view, anon_edit, org_edit, ext


def scan_sharing(g, base, internal, max_items=150, max_depth=2, always_check=False, label=""):
    """Walk a drive (breadth first, bounded) and collect risky sharing. `base` is e.g. '/me/drive' or '/sites/{id}/drive'."""
    found = {"scanned": 0, "anon_view": [], "anon_edit": [], "org_edit": [], "external": [], "errors": 0}
    queue = [(f"{base}/root/children", 0)]
    while queue and found["scanned"] < max_items:
        path, depth = queue.pop(0)
        try:
            items = g.get_all(path, {"$select": "id,name,folder,file,shared", "$top": 200}, limit=max_items)
        except Exception:
            found["errors"] += 1
            continue
        for it in items:
            if found["scanned"] >= max_items:
                break
            found["scanned"] += 1
            name = f"{label}{it.get('name')}"
            if always_check or "shared" in it:
                try:
                    av, ae, oe, ext = classify_permissions(g.get_all(f"{base}/items/{it['id']}/permissions"), internal)
                except Exception:
                    found["errors"] += 1
                    av = ae = oe = False
                    ext = []
                if ae:
                    found["anon_edit"].append(name)
                elif av:
                    found["anon_view"].append(name)
                if oe:
                    found["org_edit"].append(name)
                found["external"] += [f"{name} -> {e}" for e in ext]
            if "folder" in it and depth < max_depth:
                queue.append((f"{base}/items/{it['id']}/children", depth + 1))
    return found


def evaluate_scan(scan, area, prefix, perspective=USER, where="my files"):
    cap = f"{scan['scanned']} items scanned" + (f", {scan['errors']} unreadable" if scan["errors"] else "")
    anon = scan["anon_edit"] + scan["anon_view"]
    status = FAIL if scan["anon_edit"] else (WARN if scan["anon_view"] else PASS)
    out = [make(f"{prefix}-01", perspective, area, f"No 'Anyone' links on {where}", status,
                (f"edit: {short(scan['anon_edit'])}; view: {short(scan['anon_view'])}" if anon else "none found") + f" ({cap})", "none",
                "Open the item > Manage access > delete the 'Anyone' link, or replace it with a link for specific people.")]
    out.append(make(f"{prefix}-02", perspective, area, f"{where[0].upper() + where[1:]} shared with outside users reviewed", WARN if scan["external"] else PASS,
                    short(scan["external"]) if scan["external"] else f"none ({cap})", "only expected partners",
                    "Remove external access that is no longer needed (Manage access)."))
    out.append(make(f"{prefix}-03", perspective, area, f"Company-wide edit links on {where}", INFO if scan["org_edit"] else PASS,
                    short(scan["org_edit"]) if scan["org_edit"] else "none", "specific people for sensitive files",
                    "Organisation-wide edit links let any colleague change the file; use specific people for sensitive content."))
    return out


def user_checks(g, internal, log=lambda m: None, max_sites=15, max_items=60):
    def run():
        sites = g.get_all("/sites", {"search": "*"}, limit=max_sites)
        agg = {"scanned": 0, "anon_view": [], "anon_edit": [], "org_edit": [], "external": [], "errors": 0}
        for s in sites:
            label = f"{s.get('displayName') or s.get('name')}/"
            sc = scan_sharing(g, f"/sites/{s['id']}/drive", internal, max_items=max_items, always_check=True, label=label)
            for k in agg:
                agg[k] = agg[k] + sc[k] if isinstance(agg[k], list) else agg[k] + sc[k]
        out = [make("SP-U00", USER, AREA, "SharePoint sites visible to me", INFO, f"{len(sites)} sites (limit {max_sites})", "", "")]
        return out + evaluate_scan(agg, AREA, "SP-U", USER, "sites I can access")
    return guarded("SP-U00", USER, AREA, "Visible sites", run, log, "Sites.Read.All")
