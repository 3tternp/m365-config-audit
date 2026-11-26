# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

No version has been released yet; everything below is in the initial commit and listed under **Unreleased**.

## [Unreleased]

### Added
- **Two perspectives:** separate administrator and normal-employee sign-ins (MSAL, interactive browser or device code). Every finding is tagged *Admin* or *User*; each sign-in requests only the read-only scopes for the selected areas. Tokens are kept in memory only.
- **Teams:** group/team creation and guest-owner settings, app resource-specific consent, team inventory (ownerless, single-owner, public, guest-containing, unlabelled, guest channel rights), and, through PowerShell, external access, anonymous join, lobby, PSTN bypass and third-party storage. Employee view of joined teams, public teams, guests and single-owner teams.
- **Exchange Online:** SPF and DMARC per domain; through PowerShell, auto-forwarding, remote domains, mail-flow rules, mailbox forwarding, SMTP AUTH, modern auth, mailbox and unified audit logs, anti-phishing, Safe Links/Attachments, malware filter, DKIM and OWA storage providers. Employee view of inbox rules (external forwarding, hidden mail), automatic replies and calendar sharing.
- **SharePoint:** tenant sharing level, resharing, legacy auth, domain restrictions, idle sign-out, default link type and permission, anonymous-link and guest expiry, e-mail verification, infected-file download, "Everyone" claim, site creation and per-site sharing (Graph merged with SharePoint Online PowerShell). Employee scan of accessible sites for "Anyone" links, outside sharing and company-wide edit links.
- **OneDrive:** OneDrive sharing level, managed-device sync restriction, retention after departure, inactive and nearly-full accounts. Employee view of quota and sharing exposure in their own drive.
- **Tenant:** guest invitation and guest-access settings, tenant and app creation by users, MFA and legacy-authentication Conditional Access (or security defaults), Global Administrator count.
- **Optional read-only PowerShell collection** for settings Microsoft Graph does not expose; missing modules produce `MANUAL` findings instead of failures. A test enforces that only `Get-*` cmdlets run.
- **Desktop GUI** (CustomTkinter) with dark, light and system themes, summary cards, filters by view, area and status, search, a by-area roll-up, a fix-instruction panel and a log; plus a **CLI** (`m365_audit_cli.py`).
- **HTML, CSV and JSON reports** (tenant data is HTML-escaped).
- Offline test suite (canned Graph and PowerShell data, Graph client paging/retry, report escaping, GUI logic) running in CI on Ubuntu and Windows with Python 3.10, 3.12 and 3.13.
- README with logo, badges, permission tables, collapsible check reference, FAQ and roadmap; MIT license.
- `SECURITY.md` with a reporting process, scope and safe-use guidance.

### Security
- Values interpolated into generated PowerShell scripts (sign-in name hint and SharePoint admin URL) are validated against strict patterns; a crafted value is dropped or rejected instead of being executed. Covered by a test.

### Known limitations
- Not yet validated against a live Microsoft 365 tenant; tests use canned data only.
- Employee-view results depend on the consent a tenant grants to normal users; denied calls are reported as warnings.
- The employee file scan samples a bounded number of items, so very large tenants are not scanned exhaustively.
- A focused, CIS-inspired set of checks, not a full benchmark.

[Unreleased]: https://github.com/3tternp/m365-config-audit/commits/main
