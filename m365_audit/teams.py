"""Microsoft Teams: tenant-wide settings and team inventory (admin) and what a member can see (user)."""
from __future__ import annotations

from .common import guarded, aslist
from .models import PASS, FAIL, WARN, INFO, MANUAL, ADMIN, USER, make, short

AREA = "Teams"
TEAM_SELECT = "id,displayName,visibility,assignedLabels,createdDateTime"


# ------------------------------------------------------------------ admin
def group_settings(g):
    for s in g.get_all("/groupSettings"):
        if s.get("displayName") == "Group.Unified":
            return {v["name"]: v.get("value") for v in s.get("values", [])}
    return {}


def evaluate_group_settings(vals):
    out = []
    creation = str(vals.get("EnableGroupCreation", "true")).lower()
    out.append(make("TEAMS-A01", ADMIN, AREA, "Microsoft 365 group / team creation restricted", PASS if creation == "false" else WARN,
                    f"EnableGroupCreation={creation}" + ("" if vals else " (no Group.Unified setting: default)"), "false + creator security group",
                    "Restrict creation to a security group: Entra ID > Groups > General (or New-AzureADDirectorySetting / Update-MgDirectorySetting).",
                    reference="Group.Unified/EnableGroupCreation"))
    guest_owner = str(vals.get("AllowGuestsToBeGroupOwner", "false")).lower()
    out.append(make("TEAMS-A02", ADMIN, AREA, "Guests cannot be group owners", PASS if guest_owner == "false" else WARN,
                    f"AllowGuestsToBeGroupOwner={guest_owner}", "false", "Set AllowGuestsToBeGroupOwner to false in the Group.Unified directory setting."))
    return out


def team_info(g, t):
    """Collect the facts needed for the inventory checks for one team (each call may be denied independently)."""
    info = {"id": t["id"], "name": t.get("displayName", t["id"]), "visibility": t.get("visibility"),
            "labelled": bool(t.get("assignedLabels")), "owners": None, "guests": None, "guest_settings": None}
    try:
        info["owners"] = len(g.get_all(f"/groups/{t['id']}/owners", {"$select": "id"}))
    except Exception:
        pass
    try:
        members = g.get_all(f"/groups/{t['id']}/members/microsoft.graph.user", {"$select": "id,userType"})
        info["guests"] = sum(1 for m in members if m.get("userType") == "Guest")
    except Exception:
        pass
    try:
        info["guest_settings"] = g.get(f"/teams/{t['id']}").get("guestSettings") or {}
    except Exception:
        pass
    return info


def evaluate_inventory(infos):
    n = len(infos)
    out = []
    owners_known = [i for i in infos if i["owners"] is not None]
    ownerless = [i["name"] for i in owners_known if i["owners"] == 0]
    single = [i["name"] for i in owners_known if i["owners"] == 1]
    out.append(make("TEAMS-A04", ADMIN, AREA, "Every team has an owner", FAIL if ownerless else PASS,
                    f"{len(ownerless)} of {len(owners_known)} ownerless: " + short(ownerless) if ownerless else f"{len(owners_known)} teams checked",
                    "0 ownerless teams", "Assign owners to orphaned teams (they cannot be managed or expired)."))
    out.append(make("TEAMS-A05", ADMIN, AREA, "Teams have at least two owners", WARN if single else PASS,
                    f"{len(single)} single-owner teams: " + short(single) if single else "all have 2+ owners", ">= 2 owners",
                    "Add a second owner so the team survives staff changes."))
    public = [i["name"] for i in infos if str(i["visibility"]).lower() == "public"]
    out.append(make("TEAMS-A06", ADMIN, AREA, "Public teams reviewed", INFO if public else PASS,
                    f"{len(public)} of {n} public: " + short(public) if public else "none", "only intended public teams",
                    "Anyone in the organisation can join public teams; switch sensitive teams to Private."))
    guests = [f"{i['name']} ({i['guests']})" for i in infos if i["guests"]]
    out.append(make("TEAMS-A07", ADMIN, AREA, "Teams with guest members reviewed", INFO if guests else PASS,
                    f"{len(guests)} teams: " + short(guests) if guests else "no guests found", "guests only where needed",
                    "Review guest membership regularly (access reviews)."))
    unlabelled = [i["name"] for i in infos if not i["labelled"]]
    out.append(make("TEAMS-A08", ADMIN, AREA, "Teams carry a sensitivity label", WARN if unlabelled else PASS,
                    f"{len(unlabelled)} of {n} without a label" if unlabelled else "all labelled", "sensitivity labels applied",
                    "Publish and apply container sensitivity labels (needs Entra ID P1 + Purview)."))
    loose = [i["name"] for i in infos if (i["guest_settings"] or {}).get("allowCreateUpdateChannels") or
             (i["guest_settings"] or {}).get("allowDeleteChannels")]
    out.append(make("TEAMS-A09", ADMIN, AREA, "Guests cannot create/delete channels", WARN if loose else PASS,
                    f"{len(loose)} teams: " + short(loose) if loose else "restricted", "guests cannot manage channels",
                    "Team settings > Guest permissions: turn off channel creation and deletion."))
    return out


def admin_inventory(g, log, max_teams=200):
    teams = g.get_all("/groups", {"$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')", "$select": TEAM_SELECT, "$top": 100},
                      limit=max_teams)
    log(f"Teams: inspecting {len(teams)} teams")
    return evaluate_inventory([team_info(g, t) for t in teams])


def admin_app_settings(g):
    s = g.get("/teamwork/teamsAppSettings")
    chat = bool(s.get("isChatResourceSpecificConsentEnabled"))
    personal = bool(s.get("isUserPersonalScopeResourceSpecificConsentEnabled"))
    return [make("TEAMS-A03", ADMIN, AREA, "Resource-specific consent for apps reviewed", WARN if (chat or personal) else PASS,
                 f"chat RSC={chat}, personal-scope RSC={personal}", "disabled unless required",
                 "Teams admin center > Teams apps > Permission policies / Entra consent settings: limit who can consent to app permissions.")]


def admin_checks(g, log=lambda m: None, max_teams=200):
    out = guarded("TEAMS-A01", ADMIN, AREA, "Group creation settings", lambda: evaluate_group_settings(group_settings(g)), log,
                  "Directory.Read.All")
    out += guarded("TEAMS-A03", ADMIN, AREA, "Teams app consent settings", lambda: admin_app_settings(g), log, "TeamworkAppSettings.Read.All")
    out += guarded("TEAMS-A04", ADMIN, AREA, "Team inventory", lambda: admin_inventory(g, log, max_teams), log, "Group.Read.All")
    return out


# --------------------------------------------------------------- PowerShell-only admin settings
def evaluate_ps(data):
    """data: dict from psrunner.collect('teams'): name -> {data, error}."""
    out = []

    def got(name):
        d = data.get(name) or {}
        return d.get("data"), d.get("error")

    fed, err = got("Federation")
    if fed is None:
        out.append(make("TEAMS-A10", ADMIN, AREA, "External access (federation) settings", MANUAL, err or "not collected", "reviewed",
                        "Run Get-CsTenantFederationConfiguration in the MicrosoftTeams module and review AllowFederatedUsers / AllowPublicUsers."))
    else:
        fed = aslist(fed)[0]
        consumer = bool(fed.get("AllowPublicUsers")) or bool(fed.get("AllowTeamsConsumer"))
        out.append(make("TEAMS-A10", ADMIN, AREA, "Unmanaged (consumer) external access disabled", WARN if consumer else PASS,
                        f"AllowPublicUsers={fed.get('AllowPublicUsers')}, AllowTeamsConsumer={fed.get('AllowTeamsConsumer')}", "False",
                        "Teams admin center > Users > External access: turn off Skype/Teams consumer access unless required."))
        out.append(make("TEAMS-A11", ADMIN, AREA, "Federation with other organisations reviewed", INFO if fed.get("AllowFederatedUsers") else PASS,
                        f"AllowFederatedUsers={fed.get('AllowFederatedUsers')}", "allow-list of trusted domains",
                        "Prefer an allow list of partner domains over open federation."))
    mp, err = got("MeetingPolicy")
    if mp is None:
        out.append(make("TEAMS-A12", ADMIN, AREA, "Meeting policy (anonymous join, lobby)", MANUAL, err or "not collected", "reviewed",
                        "Run Get-CsTeamsMeetingPolicy -Identity Global and review AllowAnonymousUsersToJoinMeeting / AutoAdmittedUsers."))
    else:
        mp = aslist(mp)[0]
        anon = bool(mp.get("AllowAnonymousUsersToJoinMeeting"))
        out.append(make("TEAMS-A12", ADMIN, AREA, "Anonymous users cannot join meetings", WARN if anon else PASS,
                        f"AllowAnonymousUsersToJoinMeeting={anon}", "False", "Set-CsTeamsMeetingPolicy -AllowAnonymousUsersToJoinMeeting $false"))
        auto = str(mp.get("AutoAdmittedUsers"))
        out.append(make("TEAMS-A13", ADMIN, AREA, "Lobby: only people in the organisation bypass it", FAIL if auto == "Everyone" else
                        (PASS if auto in ("EveryoneInCompany", "EveryoneInSameAndFederatedCompany", "OrganizerOnly", "InvitedUsers") else WARN),
                        f"AutoAdmittedUsers={auto}", "EveryoneInCompany or stricter", "Set-CsTeamsMeetingPolicy -AutoAdmittedUsers EveryoneInCompany"))
        out.append(make("TEAMS-A14", ADMIN, AREA, "PSTN callers wait in the lobby", WARN if mp.get("AllowPSTNUsersToBypassLobby") else PASS,
                        f"AllowPSTNUsersToBypassLobby={mp.get('AllowPSTNUsersToBypassLobby')}", "False",
                        "Set-CsTeamsMeetingPolicy -AllowPSTNUsersToBypassLobby $false"))
    cc, err = got("ClientConfig")
    if cc is not None:
        cc = aslist(cc)[0]
        stores = [k for k in ("AllowDropBox", "AllowBox", "AllowGoogleDrive", "AllowShareFile", "AllowEgnyte") if cc.get(k)]
        out.append(make("TEAMS-A15", ADMIN, AREA, "Third-party cloud storage in Teams", WARN if stores else PASS,
                        ", ".join(stores) or "none enabled", "none", "Set-CsTeamsClientConfiguration: disable unneeded storage providers."))
    return out


# ------------------------------------------------------------------- user
def user_checks(g, log=lambda m: None, max_teams=50):
    def run():
        joined = g.get_all("/me/joinedTeams", limit=max_teams)
        out = [make("TEAMS-U01", USER, AREA, "Teams I belong to", INFO, f"{len(joined)} teams", "", "")]
        public, guest_teams, single_owner, denied_members = [], [], [], False
        for t in joined:
            name = t.get("displayName", t["id"])
            try:
                full = g.get(f"/teams/{t['id']}")
                if str(full.get("visibility")).lower() == "public":
                    public.append(name)
            except Exception:
                pass
            try:
                members = g.get_all(f"/teams/{t['id']}/members")
                if any("guest" in [r.lower() for r in (m.get("roles") or [])] for m in members):
                    guest_teams.append(name)
                if sum(1 for m in members if "owner" in [r.lower() for r in (m.get("roles") or [])]) == 1:
                    single_owner.append(name)
            except Exception:
                denied_members = True
        out.append(make("TEAMS-U02", USER, AREA, "My teams that are public", INFO if public else PASS,
                        short(public) if public else "none", "private for sensitive content",
                        "Anyone in the company can read public teams; ask the owner to make it private if it holds sensitive data."))
        if denied_members:
            out.append(make("TEAMS-U03", USER, AREA, "Guests in my teams", INFO, "membership not readable with this account's consent", "",
                            "Ask an admin to grant TeamMember.Read.All if employees should see this."))
        else:
            out.append(make("TEAMS-U03", USER, AREA, "Guests in my teams", INFO if guest_teams else PASS,
                            short(guest_teams) if guest_teams else "no guests in my teams", "only expected guests",
                            "Check that every external member is still needed."))
            out.append(make("TEAMS-U04", USER, AREA, "My teams have more than one owner", WARN if single_owner else PASS,
                            short(single_owner) if single_owner else "ok", ">= 2 owners", "Ask for a second owner."))
        return out
    return guarded("TEAMS-U01", USER, AREA, "Joined teams", run, log, "Team.ReadBasic.All")
