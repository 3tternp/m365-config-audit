# Security Policy

## Supported versions

This is an early-stage project with no tagged release yet. Security fixes are made on the `main` branch, and once releases exist only the latest release will be supported.

## Reporting a vulnerability

Please **do not** open a public issue with details of a vulnerability.

1. **Preferred:** open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting), if that button is available.
2. **Otherwise:** open a public issue titled "Security contact request" that contains **no technical details**, and the maintainer will arrange a private channel.

When you report privately, include the affected version or commit, what you observed, steps to reproduce, and the impact you expect. Remove tenant names, user addresses, tokens and any real tenant data from logs and screenshots.

This is a volunteer-maintained project, so there is no guaranteed response time, but reports are taken seriously and will be acknowledged as soon as possible. Please allow time for a fix before disclosing publicly.

## What is in scope

Issues in this tool's own code, for example:

- anything that could **expose, log or store tokens, passwords or tenant data** unexpectedly (logs, reports, the GUI, files written to disk);
- **injection** through values the tool places into PowerShell scripts or reports (sign-in names, URLs, tenant data), including HTML/script injection into exported reports;
- the tool performing a **write or state-changing request** (it is meant to use only Graph `GET` requests and `Get-*` cmdlets);
- weaknesses in how sign-in is handled (for example requesting broader scopes than the selected areas need).

Out of scope: vulnerabilities in Microsoft 365, Microsoft Graph, MSAL or the Microsoft PowerShell modules (report those to Microsoft), configuration weaknesses the tool *reports* about your own tenant, and incomplete or inaccurate check results (open a normal issue for those).

## Design principles that protect you

- **Read-only.** Only Graph `GET` requests and `Get-*` PowerShell cmdlets are used; a test fails if any other cmdlet is added.
- **No passwords handled.** Sign-in happens on Microsoft's own pages (browser or device code); the tool never sees a password. Tokens are kept in memory only, and no token cache file is written.
- **Least privilege.** Each sign-in requests only the read-only delegated permissions needed for the areas you select. Use a dedicated app registration and dedicated audit accounts, and remove the app's consent when you no longer need it.
- **Input hardening.** Values placed into PowerShell scripts (sign-in name hint, SharePoint admin URL) are validated against strict patterns first, and tenant data is HTML-escaped in reports.
- **Reports are sensitive.** Exported HTML, CSV and JSON files list teams, files, addresses and configuration weaknesses. Store and share them as confidential.

## Using it safely

- Try it first in a **test or developer tenant**: the tool has not yet been validated against a live tenant.
- Prefer a **separate administrator account with a reader role** over a Global Administrator for the admin view.
- The employee view reads that employee's mail rules, calendar and file-sharing metadata; run it only with the account owner's knowledge and consent.
- Keep your app registration's client ID private to your organisation where practical, and review its granted permissions periodically.
