"""Exchange Online / Microsoft 365 email: organisation config (admin) and a mailbox owner's view (user)."""
from __future__ import annotations

import re

from .common import guarded, aslist, domain_of
from .models import PASS, FAIL, WARN, INFO, MANUAL, ADMIN, USER, make, short

AREA = "Exchange"


# ----------------------------------------------------------------- DNS (SPF / DMARC / DKIM)
def default_lookup(name, rtype="TXT"):
    import dns.resolver
    out = []
    for r in dns.resolver.resolve(name, rtype, lifetime=6):
        out.append(r.to_text().strip('"') if rtype != "TXT" else "".join(s.decode() for s in r.strings))
    return out


def evaluate_domain_dns(domain, lookup=default_lookup):
    out = []

    def txt(name):
        try:
            return lookup(name, "TXT")
        except Exception:
            return []
    spf = next((r for r in txt(domain) if r.lower().startswith("v=spf1")), None)
    if not spf:
        out.append(make("EXO-A20", ADMIN, AREA, "SPF record published", FAIL, "no SPF record", "v=spf1 ... -all",
                        f"Publish 'v=spf1 include:spf.protection.outlook.com -all' for {domain}.", target=domain))
    else:
        m = re.search(r"([-~?+])all\b", spf)
        mech = m.group(1) if m else ""
        status = PASS if mech == "-" else (WARN if mech == "~" else FAIL)
        out.append(make("EXO-A20", ADMIN, AREA, "SPF record ends in -all", status, spf[:120], "-all (or ~all with DMARC enforcement)",
                        f"Tighten the SPF mechanism for {domain} (avoid '?all' and '+all').", target=domain))
    dmarc = next((r for r in txt("_dmarc." + domain) if r.lower().startswith("v=dmarc1")), None)
    if not dmarc:
        out.append(make("EXO-A21", ADMIN, AREA, "DMARC record published", FAIL, "no DMARC record", "p=quarantine or p=reject",
                        f"Publish a _dmarc.{domain} TXT record, start with p=none and move to reject.", target=domain))
    else:
        p = re.search(r"\bp=(\w+)", dmarc, re.I)
        pol = (p.group(1).lower() if p else "none")
        out.append(make("EXO-A21", ADMIN, AREA, "DMARC policy enforces (quarantine/reject)", PASS if pol in ("quarantine", "reject") else WARN,
                        dmarc[:120], "p=quarantine or p=reject", f"Move the DMARC policy for {domain} from p=none to quarantine/reject after monitoring.",
                        target=domain))
    return out


# --------------------------------------------------------------------- admin (PowerShell data)
def evaluate_ps(data):
    out = []

    def rows(name):
        d = data.get(name) or {}
        return (aslist(d.get("data")) if d.get("error") is None and d.get("data") is not None else None), d.get("error")

    def manual(cid, title, err, how):
        out.append(make(cid, ADMIN, AREA, title, MANUAL, err or "not collected", "reviewed", how))

    # --- forwarding
    pol, err = rows("OutboundSpam")
    if pol is None:
        manual("EXO-A01", "Automatic external forwarding blocked", err, "Get-HostedOutboundSpamFilterPolicy | fl Name,AutoForwardingMode  (want Off or Automatic)")
    else:
        on = [p.get("Name") for p in pol if str(p.get("AutoForwardingMode")) == "On"]
        out.append(make("EXO-A01", ADMIN, AREA, "Automatic external forwarding blocked", FAIL if on else PASS,
                        "AutoForwardingMode=On in: " + short(on) if on else "Off/Automatic in all policies", "Off or Automatic",
                        "Set-HostedOutboundSpamFilterPolicy -Identity <policy> -AutoForwardingMode Off"))
    rd, err = rows("RemoteDomain")
    if rd is not None:
        bad = [r.get("Name") for r in rd if r.get("AutoForwardEnabled") and (r.get("DomainName") in ("*", None) or r.get("Name") == "Default")]
        out.append(make("EXO-A02", ADMIN, AREA, "Default remote domain does not allow auto-forward", FAIL if bad else PASS,
                        "AutoForwardEnabled=True on default" if bad else "disabled", "False", "Set-RemoteDomain Default -AutoForwardEnabled $false"))
    accepted = {str(a.get("DomainName", "")).lower() for a in (rows("AcceptedDomains")[0] or [])}
    fw, err = rows("Forwarding")
    if fw is None:
        manual("EXO-A04", "Mailbox-level forwarding reviewed", err, "Get-Mailbox -ResultSize Unlimited | ? ForwardingSmtpAddress")
    else:
        ext = [f"{m.get('UserPrincipalName')} -> {m.get('ForwardingSmtpAddress')}" for m in fw
               if m.get("ForwardingSmtpAddress") and (not accepted or domain_of(str(m["ForwardingSmtpAddress"])) not in accepted)]
        internal = len(fw) - len(ext)
        out.append(make("EXO-A04", ADMIN, AREA, "No mailbox forwards to external addresses", FAIL if ext else (WARN if internal else PASS),
                        ("external: " + short(ext)) if ext else (f"{internal} internal forwards" if internal else "no forwarding configured"), "none",
                        "Remove ForwardingSmtpAddress (Set-Mailbox <user> -ForwardingSmtpAddress $null); investigate as possible compromise."))
    tr, err = rows("TransportRules")
    if tr is None:
        manual("EXO-A03", "Mail flow rules reviewed", err, "Get-TransportRule | fl Name,State,RedirectMessageTo,BlindCopyTo,SetSCL")
    else:
        bypass = [r.get("Name") for r in tr if str(r.get("SetSCL")) == "-1" and r.get("State") == "Enabled"]
        redirect = [r.get("Name") for r in tr if r.get("State") == "Enabled" and (aslist(r.get("RedirectMessageTo")) or aslist(r.get("BlindCopyTo")) or aslist(r.get("CopyTo")))]
        out.append(make("EXO-A03", ADMIN, AREA, "No mail flow rule bypasses spam filtering (SCL -1)", FAIL if bypass else PASS,
                        short(bypass) if bypass else "none", "none", "Remove or narrow rules that set SCL to -1; allow-lists defeat anti-spam."))
        out.append(make("EXO-A05", ADMIN, AREA, "Mail flow rules that redirect / copy mail reviewed", WARN if redirect else PASS,
                        short(redirect) if redirect else "none", "justified rules only", "Confirm each redirect/BCC rule is legitimate and not sending mail outside."))
    # --- protocol & audit
    tc, err = rows("TransportConfig")
    if tc is not None and tc:
        dis = tc[0].get("SmtpClientAuthenticationDisabled")
        out.append(make("EXO-A06", ADMIN, AREA, "SMTP AUTH (basic) disabled organisation-wide", PASS if dis else WARN, f"SmtpClientAuthenticationDisabled={dis}", "True",
                        "Set-TransportConfig -SmtpClientAuthenticationDisabled $true (enable per mailbox only where needed)."))
    oc, err = rows("OrganizationConfig")
    if oc:
        o = oc[0]
        out.append(make("EXO-A07", ADMIN, AREA, "Modern authentication enabled", PASS if o.get("OAuth2ClientProfileEnabled") else FAIL,
                        f"OAuth2ClientProfileEnabled={o.get('OAuth2ClientProfileEnabled')}", "True", "Set-OrganizationConfig -OAuth2ClientProfileEnabled $true"))
        out.append(make("EXO-A08", ADMIN, AREA, "Mailbox auditing not disabled", FAIL if o.get("AuditDisabled") else PASS,
                        f"AuditDisabled={o.get('AuditDisabled')}", "False", "Set-OrganizationConfig -AuditDisabled $false"))
        out.append(make("EXO-A09", ADMIN, AREA, "Customer Lockbox", PASS if o.get("CustomerLockboxEnabled") else INFO,
                        f"CustomerLockboxEnabled={o.get('CustomerLockboxEnabled')}", "True where licensed", "Enable Customer Lockbox (E5 / add-on)."))
    ac, err = rows("AuditConfig")
    if ac:
        on = ac[0].get("UnifiedAuditLogIngestionEnabled")
        out.append(make("EXO-A10", ADMIN, AREA, "Unified audit log enabled", PASS if on else FAIL, f"UnifiedAuditLogIngestionEnabled={on}", "True",
                        "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true"))
    # --- protection
    ap, err = rows("AntiPhish")
    if ap is not None:
        good = [p for p in ap if p.get("Enabled") and p.get("EnableSpoofIntelligence") and p.get("EnableMailboxIntelligence")]
        out.append(make("EXO-A11", ADMIN, AREA, "Anti-phishing with spoof and mailbox intelligence", PASS if good else WARN,
                        f"{len(good)} of {len(ap)} policies fully enabled", ">= 1 policy", "Enable spoof intelligence and mailbox intelligence in the anti-phishing policy."))
    sl, _ = rows("SafeLinks")
    sa, _ = rows("SafeAttachments")
    if sl is not None or sa is not None:
        have = bool(sl) or bool(sa)
        out.append(make("EXO-A12", ADMIN, AREA, "Safe Links / Safe Attachments policies exist", PASS if have else INFO,
                        f"Safe Links={len(sl or [])}, Safe Attachments={len(sa or [])}", ">= 1 each (Defender for Office 365)",
                        "Create Safe Links / Safe Attachments policies (needs Defender for Office 365 Plan 1/2)."))
    mw, _ = rows("Malware")
    if mw:
        off = [m.get("Name") for m in mw if not m.get("EnableFileFilter")]
        out.append(make("EXO-A13", ADMIN, AREA, "Common attachment type filter enabled", WARN if off else PASS, short(off) if off else "enabled", "True",
                        "Set-MalwareFilterPolicy -EnableFileFilter $true"))
    dk, _ = rows("Dkim")
    if dk is not None:
        off = [d.get("Domain") for d in dk if not d.get("Enabled") and not str(d.get("Domain", "")).endswith(".onmicrosoft.com")]
        out.append(make("EXO-A14", ADMIN, AREA, "DKIM signing enabled for custom domains", FAIL if off else PASS, short(off) if off else "all enabled", "Enabled",
                        "Set-DkimSigningConfig -Identity <domain> -Enabled $true (after publishing the selector CNAMEs)."))
    ow, _ = rows("OwaPolicy")
    if ow is not None:
        bad = [p.get("Name") for p in ow if p.get("AdditionalStorageProvidersAvailable")]
        out.append(make("EXO-A15", ADMIN, AREA, "Outlook on the web: no third-party storage providers", WARN if bad else PASS, short(bad) if bad else "disabled", "False",
                        "Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $false"))
    return out


def admin_dns(domains, lookup=default_lookup, log=lambda m: None):
    out = []
    for d in domains:
        if d.lower().endswith(".onmicrosoft.com"):
            continue
        out += evaluate_domain_dns(d, lookup)
    return out


def admin_checks(g, ps_data=None, log=lambda m: None, lookup=None):
    lookup = lookup or default_lookup      # resolved at call time so tests can substitute it
    out = []

    def dns_part():
        domains = [d["id"] for d in g.get_all("/domains") if d.get("isVerified") and "Email" in (d.get("supportedServices") or ["Email"])]
        return admin_dns(domains, lookup, log)
    out += guarded("EXO-A20", ADMIN, AREA, "SPF / DMARC", dns_part, log, "Directory.Read.All")
    if ps_data is not None:
        out += evaluate_ps(ps_data)
    else:
        out.append(make("EXO-A00", ADMIN, AREA, "Exchange Online organisation settings", MANUAL, "PowerShell collection disabled",
                        "reviewed", "Enable the PowerShell option (ExchangeOnlineManagement module) for forwarding, anti-phish, DKIM and audit checks."))
    return out


# ------------------------------------------------------------------------------- user
def _addrs(lst):
    return [(x.get("emailAddress") or {}).get("address", "") for x in (lst or [])]


def evaluate_rules(rules, internal):
    """rules: inbox messageRules; internal: set of internal domains."""
    out, ext, hide = [], [], []
    for r in rules:
        if not r.get("isEnabled", True):
            continue
        a = r.get("actions") or {}
        targets = _addrs(a.get("forwardTo")) + _addrs(a.get("forwardAsAttachmentTo")) + _addrs(a.get("redirectTo"))
        external = [t for t in targets if t and domain_of(t) not in internal]
        if external:
            ext.append(f"{r.get('displayName')} -> {', '.join(external)}")
        if a.get("delete") or a.get("permanentDelete") or (a.get("markAsRead") and (r.get("conditions") or {})):
            hide.append(r.get("displayName"))
    out.append(make("EXO-U01", USER, AREA, "No inbox rule forwards my mail outside the company", FAIL if ext else PASS,
                    short(ext) if ext else f"{len(rules)} rules checked", "none",
                    "Delete the rule in Outlook > Rules, then change your password and report it: external forwarding is a common sign of a hijacked mailbox."))
    out.append(make("EXO-U02", USER, AREA, "No rule silently deletes or hides incoming mail", WARN if hide else PASS,
                    short(hide) if hide else "none", "none",
                    "Review these rules; attackers use delete / mark-as-read rules to hide replies from you."))
    return out


def evaluate_autoreply(settings):
    ar = (settings or {}).get("automaticRepliesSetting") or {}
    status, aud = ar.get("status", "disabled"), ar.get("externalAudience", "none")
    bad = status != "disabled" and aud == "all"
    return [make("EXO-U03", USER, AREA, "Automatic replies are not sent to everyone outside", WARN if bad else PASS,
                 f"status={status}, externalAudience={aud}", "contacts only or none",
                 "Outlook > Automatic replies: limit the external audience to your contacts (out-of-office replies leak travel dates and reveal valid addresses).")]


def evaluate_calendar(perms, internal):
    bad = []
    for p in perms:
        addr = (p.get("emailAddress") or {}).get("address", "")
        role = p.get("role", "")
        if addr and domain_of(addr) not in internal and role not in ("none", ""):
            bad.append(f"{addr} ({role})")
        elif role in ("write", "delegateWithPrivateEventAccess") and p.get("isInsideOrganization") is False:
            bad.append(f"{addr or p.get('id')} ({role})")
    return [make("EXO-U04", USER, AREA, "My calendar is not shared with outside addresses", WARN if bad else PASS,
                 short(bad) if bad else f"{len(perms)} permission entries", "internal sharing only",
                 "Outlook > Calendar > Sharing and permissions: remove external entries or reduce them to free/busy.")]


def internal_domains(g):
    me = g.get("/me", {"$select": "userPrincipalName,mail"})
    doms = {domain_of(me.get("userPrincipalName", "")), domain_of(me.get("mail") or "")}
    try:
        for o in g.get_all("/organization"):
            doms |= {v["name"].lower() for v in o.get("verifiedDomains", [])}
    except Exception:
        pass
    return {d for d in doms if d}


def user_checks(g, log=lambda m: None):
    internal = internal_domains(g)
    out = guarded("EXO-U01", USER, AREA, "Inbox rules", lambda: evaluate_rules(g.get_all("/me/mailFolders/inbox/messageRules"), internal), log, "Mail.Read")
    out += guarded("EXO-U03", USER, AREA, "Automatic replies", lambda: evaluate_autoreply(g.get("/me/mailboxSettings")), log, "MailboxSettings.Read")
    out += guarded("EXO-U04", USER, AREA, "Calendar sharing", lambda: evaluate_calendar(g.get_all("/me/calendar/calendarPermissions"), internal), log, "Calendars.Read")
    return out
