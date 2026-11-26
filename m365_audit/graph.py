"""Minimal Microsoft Graph client (read-only GETs, paging, throttling retry)."""
from __future__ import annotations

import time

BASE = "https://graph.microsoft.com/v1.0"


class GraphError(Exception):
    def __init__(self, status, code="", message=""):
        super().__init__(f"HTTP {status} {code}: {message}"[:300])
        self.status, self.code, self.message = status, code, message

    @property
    def denied(self):
        """True when the signed-in account/consent simply lacks access (an expected outcome, not a bug)."""
        return self.status in (401, 403)


class Graph:
    def __init__(self, token_provider, session=None, base=BASE, sleep=time.sleep):
        self._token = token_provider          # callable -> bearer token (never stored on disk)
        self.base = base
        self._sleep = sleep
        if session is None:
            import requests
            session = requests.Session()
        self.http = session

    def _request(self, url, params=None, headers=None):
        for attempt in range(4):
            r = self.http.get(url, params=params, timeout=60,
                              headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/json",
                                       "ConsistencyLevel": "eventual", **(headers or {})})
            if r.status_code in (429, 503) and attempt < 3:
                self._sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 30))
                continue
            return r
        return r

    def _check(self, r):
        if r.status_code >= 400:
            try:
                err = r.json().get("error", {})
            except Exception:
                err = {}
            raise GraphError(r.status_code, err.get("code", ""), err.get("message", r.text[:150]))

    def get(self, path, params=None):
        url = path if path.startswith("http") else self.base + path
        r = self._request(url, params)
        self._check(r)
        return r.json() if r.content else {}

    def get_all(self, path, params=None, limit=2000):
        """Follow @odata.nextLink; returns the combined 'value' list (capped at `limit`)."""
        out, url, p = [], (path if path.startswith("http") else self.base + path), params
        while url and len(out) < limit:
            r = self._request(url, p)
            self._check(r)
            data = r.json()
            out.extend(data.get("value", []))
            url, p = data.get("@odata.nextLink"), None
        return out[:limit]

    def get_text(self, path):
        url = path if path.startswith("http") else self.base + path
        r = self._request(url)
        self._check(r)
        return r.text
