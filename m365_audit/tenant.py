"""Entra ID / tenant settings that govern Teams, Exchange, SharePoint and OneDrive access (admin)."""
from __future__ import annotations

from .common import guarded, first
from .models import PASS, FAIL, WARN, ADMIN, make

AREA = "Tenant"
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
GUEST_ROLE = {"10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited access (default)",
              "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted access",
              "a0b1b346-4d3e-4e8b-98f8-753987be4970": "same as members"}


def evaluate_authz(p):
    out = []
    inv = str(p.get("allowInvitesFrom"))
    out.append(make("TEN-A01", ADMIN, AREA, "Guest invitations limited to admins / guest inviters",
                    PASS if inv in ("adminsAndGuestInviters", "none") else (WARN if inv == "adminsGuestInvitersAndAllMembers" else FAIL),
                    f"allowInvitesFrom={inv}", "adminsAndGuestInviters or none",
                    "Entra ID > External Identities > External collaboration settings: restrict who can invite guests."))
    role = p.get("guestUserRoleId")
    out.append(make("TEN-A02", ADMIN, AREA, "Guest user access is restricted", FAIL if role == "a0b1b346-4d3e-4e8b-98f8-753987be4970" else PASS,
                    GUEST_ROLE.get(role, role), "limited or restricted access", "Set guest user access to 'limited' or 'restricted'."))
    perms = p.get("defaultUserRolePermissions") or {}
    out.append(make("TEN-A03", ADMIN, AREA, "Users cannot create tenants", WARN if perms.get("allowedToCreateTenants") else PASS,
                    f"allowedToCreateTenants={perms.get('allowedToCreateTenants')}", "False",
                    "Entra ID > Users > User settings: restrict tenant creation."))
    out.append(make("TEN-A07", ADMIN, AREA, "Users cannot register applications", WARN if perms.get("allowedToCreateApps") else PASS,
                    f"allowedToCreateApps={perms.get('allowedToCreateApps')}", "False",
                    "Entra ID > Users > User settings: 'Users can register applications' = No (limits illicit consent)."))
    return out


def evaluate_ca(policies, security_defaults):
    enabled = [p for p in policies if p.get("state") == "enabled"]

    def grants(p):
        return [c.lower() for c in ((p.get("grantControls") or {}).get("builtInControls") or [])]

    def cond(p, key, sub):
        return ((p.get("conditions") or {}).get(key) or {}).get(sub) or []

    mfa_all = [p.get("displayName") for p in enabled if "mfa" in grants(p) and "All" in cond(p, "users", "includeUsers")
               and "All" in cond(p, "applications", "includeApplications")]
    legacy = [p.get("displayName") for p in enabled if "block" in grants(p) and {"exchangeActiveSync", "other"} <= set(
        (p.get("conditions") or {}).get("clientAppTypes") or [])]
    out = []
    if mfa_all or (not policies and security_defaults):
        out.append(make("TEN-A04", ADMIN, AREA, "MFA required for all users", PASS, "; ".join(mfa_all) or "security defaults enabled", "enforced"))
    else:
        out.append(make("TEN-A04", ADMIN, AREA, "MFA required for all users", FAIL, "no enabled policy requires MFA for all users and apps", "enforced",
                        "Create a Conditional Access policy: All users, All cloud apps, Grant: Require multifactor authentication (or enable security defaults)."))
    if legacy or (not policies and security_defaults):
        out.append(make("TEN-A05", ADMIN, AREA, "Legacy authentication blocked", PASS, "; ".join(legacy) or "security defaults enabled", "blocked"))
    else:
        out.append(make("TEN-A05", ADMIN, AREA, "Legacy authentication blocked", FAIL, "no policy blocks legacy client apps", "blocked",
                        "Create a Conditional Access policy that blocks Exchange ActiveSync and 'other clients' (protects Exchange, SharePoint, Teams from password spray)."))
    return out


def evaluate_global_admins(n):
    status = PASS if 2 <= n <= 4 else (FAIL if n > 5 else WARN)
    return [make("TEN-A06", ADMIN, AREA, "Global Administrator count is small (2-4)", status, f"{n} Global Administrators", "2 to 4",
                 "Keep 2-4 Global Admins (two break-glass + few operators); use least-privileged roles for the rest.")]


def admin_checks(g, log=lambda m: None):
    out = guarded("TEN-A01", ADMIN, AREA, "Authorization policy", lambda: evaluate_authz(first(g.get("/policies/authorizationPolicy"))), log, "Policy.Read.All")

    def ca():
        pols = g.get_all("/identity/conditionalAccess/policies")
        sd = False
        if not pols:
            sd = bool(g.get("/policies/identitySecurityDefaultsEnforcementPolicy").get("isEnabled"))
        return evaluate_ca(pols, sd)
    out += guarded("TEN-A04", ADMIN, AREA, "Conditional Access", ca, log, "Policy.Read.All")
    out += guarded("TEN-A06", ADMIN, AREA, "Global administrators",
                   lambda: evaluate_global_admins(len(g.get_all(f"/directoryRoles/roleTemplateId={GLOBAL_ADMIN_TEMPLATE}/members"))), log,
                   "RoleManagement.Read.Directory")
    return out
