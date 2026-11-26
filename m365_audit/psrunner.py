"""Read-only PowerShell collection for settings Microsoft Graph does not expose
(Exchange Online org config, Teams policies, SharePoint tenant settings).

Only Get-* cmdlets are run (a test enforces this). The administrator signs in through the module's own
interactive prompt; this tool never sees the password or token.
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import sys

MARK = "<<<M365AUDIT-JSON>>>"

SERVICES = {
    "exchange": {
        "module": "ExchangeOnlineManagement", "exe": ("pwsh", "powershell"),
        "connect": "Connect-ExchangeOnline -ShowBanner:$false{upn}", "disconnect": "Disconnect-ExchangeOnline -Confirm:$false",
        "commands": {
            "OrganizationConfig": "Get-OrganizationConfig | Select-Object OAuth2ClientProfileEnabled,AuditDisabled,CustomerLockboxEnabled,MailTipsExternalRecipientsTipsEnabled",
            "OutboundSpam": "Get-HostedOutboundSpamFilterPolicy | Select-Object Name,AutoForwardingMode",
            "RemoteDomain": "Get-RemoteDomain | Select-Object Name,DomainName,AutoForwardEnabled",
            "TransportRules": "Get-TransportRule | Select-Object Name,State,RedirectMessageTo,BlindCopyTo,CopyTo,SetSCL",
            "TransportConfig": "Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled",
            "Forwarding": "Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } | Select-Object UserPrincipalName,ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward",
            "AntiPhish": "Get-AntiPhishPolicy | Select-Object Name,Enabled,EnableMailboxIntelligence,EnableSpoofIntelligence",
            "SafeLinks": "Get-SafeLinksPolicy | Select-Object Name,EnableSafeLinksForEmail",
            "SafeAttachments": "Get-SafeAttachmentPolicy | Select-Object Name,Enable",
            "Dkim": "Get-DkimSigningConfig | Select-Object Domain,Enabled",
            "OwaPolicy": "Get-OwaMailboxPolicy | Select-Object Name,AdditionalStorageProvidersAvailable",
            "AuditConfig": "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled",
            "Malware": "Get-MalwareFilterPolicy | Select-Object Name,EnableFileFilter",
            "AcceptedDomains": "Get-AcceptedDomain | Select-Object DomainName,DomainType",
        },
    },
    "teams": {
        "module": "MicrosoftTeams", "exe": ("pwsh", "powershell"),
        "connect": "Connect-MicrosoftTeams{teamsupn}", "disconnect": "Disconnect-MicrosoftTeams",
        "commands": {
            "Federation": "Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers,AllowPublicUsers,AllowTeamsConsumer",
            "MeetingPolicy": "Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting,AutoAdmittedUsers,AllowPSTNUsersToBypassLobby",
            "ClientConfig": "Get-CsTeamsClientConfiguration | Select-Object AllowDropBox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte",
        },
    },
    "spo": {
        # The SharePoint Online module needs Windows PowerShell 5.1
        "module": "Microsoft.Online.SharePoint.PowerShell", "exe": ("powershell",),
        "connect": "Connect-SPOService -Url '{adminurl}'", "disconnect": "Disconnect-SPOService",
        "commands": {
            "Tenant": "Get-SPOTenant | Select-Object SharingCapability,OneDriveSharingCapability,DefaultSharingLinkType,DefaultLinkPermission,"
                      "RequireAnonymousLinksExpireInDays,ExternalUserExpirationRequired,ExternalUserExpireInDays,PreventExternalUsersFromResharing,"
                      "EmailAttestationRequired,DisallowInfectedFileDownload,ShowEveryoneClaim,ShowEveryoneExceptExternalUsersClaim,"
                      "LegacyAuthProtocolsEnabled,ConditionalAccessPolicy,SharingDomainRestrictionMode,OrphanedPersonalSitesRetentionPeriod",
            "Sites": "Get-SPOSite -Limit All | Select-Object Url,SharingCapability,LockState",
        },
    },
}


UPN_RE = re.compile(r"^[\w.%+\-]+@[\w.\-]+$")
ADMIN_URL_RE = re.compile(r"^https://[a-z0-9\-]+-admin\.sharepoint\.com/?$")


def build_script(service, upn=None, adminurl=None):
    """Values interpolated into the script are validated first, so a crafted sign-in name or URL cannot inject PowerShell."""
    s = SERVICES[service]
    if upn and not UPN_RE.match(upn):
        upn = None                                        # only a convenience hint; drop it rather than risk injection
    if service == "spo" and not (adminurl and ADMIN_URL_RE.match(adminurl)):
        raise ValueError("invalid SharePoint admin URL")
    connect = s["connect"].format(upn=f" -UserPrincipalName '{upn}'" if upn else "",
                                  teamsupn=f" -AccountId '{upn}'" if upn else "", adminurl=adminurl or "")
    lines = ["$ErrorActionPreference='Stop'", "$ProgressPreference='SilentlyContinue'", "$out=@{}",
             f"function Done {{ Write-Output '{MARK}'; $out | ConvertTo-Json -Depth 6 -Compress }}",
             f"if (-not (Get-Module -ListAvailable -Name {s['module']})) {{ $out['__connect']=@{{data=$null;error='PowerShell module {s['module']} is not installed. Run: Install-Module {s['module']} -Scope CurrentUser'}}; Done; exit 0 }}",
             f"try {{ Import-Module {s['module']}; {connect} }} catch {{ $out['__connect']=@{{data=$null;error=$_.Exception.Message}}; Done; exit 0 }}",
             "function Run($n,[scriptblock]$sb){ try{ $out[$n]=@{data=@(& $sb);error=$null} }catch{ $out[$n]=@{data=$null;error=$_.Exception.Message} } }"]
    for name, cmd in s["commands"].items():
        lines.append(f"Run '{name}' {{ {cmd} }}")
    lines += [f"try {{ {s['disconnect']} }} catch {{}}", "Done"]
    return "\n".join(lines)


def find_exe(candidates):
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
    return None


def parse_output(stdout: str):
    if MARK not in stdout:
        raise ValueError("no result marker in PowerShell output")
    return json.loads(stdout.split(MARK, 1)[1].strip())


def collect(service, upn=None, adminurl=None, timeout=1200, log=lambda m: None, runner=subprocess.run):
    """Run the read-only cmdlets for one service. Returns {name: {data, error}}; never raises for missing tooling."""
    s = SERVICES[service]
    names = list(s["commands"])
    exe = find_exe(s["exe"])
    if not exe:
        return {n: {"data": None, "error": f"PowerShell ({'/'.join(s['exe'])}) not found"} for n in names}
    try:
        script = build_script(service, upn, adminurl)
    except ValueError as e:
        return {n: {"data": None, "error": str(e)} for n in names}
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    log(f"PowerShell: collecting {service} settings (sign in when the Microsoft prompt appears) ...")
    try:
        p = runner([exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc], capture_output=True, text=True,
                   timeout=timeout, creationflags=flags)
        data = parse_output(p.stdout)
    except Exception as e:
        return {n: {"data": None, "error": f"PowerShell collection failed: {type(e).__name__}: {str(e)[:120]}"} for n in names}
    if "__connect" in data and data["__connect"].get("error"):
        err = data["__connect"]["error"]
        return {n: {"data": None, "error": err} for n in names}
    return data
