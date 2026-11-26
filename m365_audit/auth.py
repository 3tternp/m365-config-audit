"""Interactive sign-in with MSAL. Tokens are kept in memory only (no cache file is written).

Two independent sessions are used: one for an administrator account and one for a normal employee
account, so every finding is tagged with the perspective that produced it. Only read scopes are requested.
"""
from __future__ import annotations

GRAPH_SCOPE = "https://graph.microsoft.com/"

# Delegated, read-only scopes per area. Many of the admin ones need admin consent in your tenant.
ADMIN_SCOPES = {
    "Teams": ["Group.Read.All", "Team.ReadBasic.All", "TeamSettings.Read.All", "TeamMember.Read.All",
              "TeamworkAppSettings.Read.All", "Directory.Read.All"],
    "Exchange": ["Directory.Read.All"],                      # accepted domains for SPF/DKIM/DMARC checks
    "SharePoint": ["SharePointTenantSettings.Read.All", "Sites.Read.All"],
    "OneDrive": ["SharePointTenantSettings.Read.All", "Reports.Read.All"],
    "Tenant": ["Policy.Read.All", "Directory.Read.All", "Organization.Read.All", "RoleManagement.Read.Directory"],
}
USER_SCOPES = {
    "Teams": ["Team.ReadBasic.All", "User.Read"],
    "Exchange": ["Mail.Read", "MailboxSettings.Read", "Calendars.Read", "User.Read"],
    "SharePoint": ["Sites.Read.All", "User.Read"],
    "OneDrive": ["Files.Read", "User.Read"],
    "Tenant": ["User.Read"],
}


def scopes_for(perspective: str, areas) -> list[str]:
    table = ADMIN_SCOPES if perspective == "Admin" else USER_SCOPES
    names = sorted({s for a in areas for s in table.get(a, [])})
    return [GRAPH_SCOPE + n for n in names]


class SignIn:
    """One signed-in account (admin or user)."""

    def __init__(self, perspective, tenant, client_id):
        try:
            import msal
        except ImportError as e:
            raise RuntimeError("msal is required: pip install -r requirements.txt") from e
        self.perspective, self.tenant, self.client_id = perspective, tenant, client_id
        self.app = msal.PublicClientApplication(client_id, authority=f"https://login.microsoftonline.com/{tenant}")
        self.scopes, self.account, self.claims = [], None, {}

    def login(self, areas, device_code=False, show_code=lambda msg: None):
        """Blocks until the person finishes signing in. Returns the account's sign-in name."""
        self.scopes = scopes_for(self.perspective, areas)
        if device_code:
            flow = self.app.initiate_device_flow(scopes=self.scopes)
            if "user_code" not in flow:
                raise RuntimeError(flow.get("error_description", "could not start device-code sign-in"))
            show_code(flow["message"])
            result = self.app.acquire_token_by_device_flow(flow)
        else:
            result = self.app.acquire_token_interactive(self.scopes, prompt="select_account")
        if "access_token" not in result:
            raise RuntimeError(result.get("error_description") or result.get("error") or "sign-in failed")
        self.claims = result.get("id_token_claims", {}) or {}
        accounts = self.app.get_accounts()
        self.account = accounts[0] if accounts else None
        return self.name

    @property
    def name(self):
        return self.claims.get("preferred_username") or self.claims.get("upn") or "signed in"

    @property
    def tenant_id(self):
        return self.claims.get("tid", "")

    def token(self):
        """Fresh access token (silent refresh from the in-memory cache)."""
        res = self.app.acquire_token_silent(self.scopes, account=self.account)
        if not res or "access_token" not in res:
            raise RuntimeError("Session expired; please sign in again.")
        return res["access_token"]
