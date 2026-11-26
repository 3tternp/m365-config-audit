"""Desktop GUI (CustomTkinter) for the Microsoft 365 configuration audit.

Sign in once as an administrator and once as a normal employee: every finding is tagged with the
perspective that produced it. Passwords are typed into Microsoft's own sign-in page, never into this tool,
and tokens are kept in memory only.
"""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from . import gui_model as gm, report
from .auth import SignIn
from .graph import Graph
from .models import AREAS, STATUSES
from .scanner import ScanOptions, run_scan

ASSETS = Path(__file__).resolve().parent.parent / "assets"
STATUS_COLOR = {"FAIL": "#e5484d", "WARN": "#f5a524", "PASS": "#30a46c", "INFO": "#3e8ed0", "ERROR": "#8e4ec6", "MANUAL": "#8b8d98"}
ROW_DARK = {"FAIL": "#4a2326", "WARN": "#4a3a1b", "PASS": "#1d3a2b", "INFO": "#1c3550", "ERROR": "#3a2750", "MANUAL": "#33363b"}
ROW_LIGHT = {"FAIL": "#fde3e4", "WARN": "#fff0d4", "PASS": "#e0f4e9", "INFO": "#ddeafa", "ERROR": "#eddff9", "MANUAL": "#eceef1"}
MUTED = ("gray40", "gray65")
OUTLINE = dict(fg_color="transparent", border_width=1, text_color=("gray10", "gray90"))


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("Microsoft 365 Config Auditor - Teams · Exchange · SharePoint · OneDrive")
        self.geometry("1400x880")
        self.minsize(1120, 720)
        self.q = queue.Queue()
        self.results, self.meta, self.worker = [], {}, None
        self.sessions = {}            # perspective -> (SignIn, frozenset(areas))
        self._rows = {}
        self._build_sidebar()
        self._build_main()
        self._style_tree()
        self.after(150, self._set_icon)
        self.after(100, self._pump)

    # ------------------------------------------------------------------ chrome
    def _set_icon(self):
        try:
            if sys.platform == "win32":
                self.iconbitmap(str(ASSETS / "icon.ico"))
            else:
                self.iconphoto(True, tk.PhotoImage(file=str(ASSETS / "icon_64.png")))
        except Exception:
            pass

    def _label(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=ctk.CTkFont(size=11, weight="bold"), text_color=MUTED).pack(anchor="w", padx=20, pady=(14, 2))

    def _build_sidebar(self):
        sb = ctk.CTkScrollableFrame(self, width=320, corner_radius=0)
        sb.pack(side="left", fill="y")
        ctk.CTkLabel(sb, text="Microsoft 365 Auditor", font=ctk.CTkFont(size=22, weight="bold")).pack(anchor="w", padx=20, pady=(18, 0))
        ctk.CTkLabel(sb, text="Teams · Exchange · SharePoint · OneDrive", text_color=MUTED).pack(anchor="w", padx=20)

        self._label(sb, "TENANT")
        self.tenant = ctk.CTkEntry(sb, placeholder_text="contoso.onmicrosoft.com or tenant ID")
        self.tenant.pack(fill="x", padx=20)
        self.client = ctk.CTkEntry(sb, placeholder_text="App (client) ID of your app registration")
        self.client.pack(fill="x", padx=20, pady=(6, 0))
        ctk.CTkLabel(sb, text="Public-client app registration with read-only delegated permissions; see README.", wraplength=270,
                     justify="left", font=ctk.CTkFont(size=11), text_color=MUTED).pack(anchor="w", padx=20, pady=(4, 0))

        self._label(sb, "SIGN IN (one account per perspective)")
        self.chip = {}
        for persp, label in (("Admin", "Administrator"), ("User", "Employee (normal user)")):
            row = ctk.CTkFrame(sb, corner_radius=10)
            row.pack(fill="x", padx=20, pady=4)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=12, pady=(8, 0))
            st = ctk.CTkLabel(row, text="not signed in", text_color=MUTED, anchor="w")
            st.pack(anchor="w", padx=12)
            bar = ctk.CTkFrame(row, fg_color="transparent")
            bar.pack(fill="x", padx=8, pady=(4, 8))
            ctk.CTkButton(bar, text="Sign in", width=110, height=28, command=lambda p=persp: self.sign_in(p)).pack(side="left", padx=4)
            ctk.CTkButton(bar, text="Sign out", width=80, height=28, command=lambda p=persp: self.sign_out(p), **OUTLINE).pack(side="left")
            self.chip[persp] = st

        self._label(sb, "AREAS")
        self.area_vars = {}
        for a in AREAS:
            v = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(sb, text=a, variable=v).pack(anchor="w", padx=24, pady=3)
            self.area_vars[a] = v

        self._label(sb, "OPTIONS")
        self.use_ps = ctk.CTkCheckBox(sb, text="Use PowerShell modules (admin depth)")
        self.use_ps.select()
        self.use_ps.pack(anchor="w", padx=24, pady=3)
        ctk.CTkLabel(sb, text="Adds Exchange, Teams policy and SharePoint tenant checks that Graph cannot read. Needs the "
                              "ExchangeOnlineManagement, MicrosoftTeams and SharePoint Online modules; you sign in again in their prompts.",
                     wraplength=235, justify="left", anchor="w", font=ctk.CTkFont(size=11), text_color=MUTED).pack(anchor="w", padx=(46, 10), pady=(0, 4))
        self.device = ctk.CTkCheckBox(sb, text="Device-code sign-in (no browser redirect)")
        self.device.pack(anchor="w", padx=24, pady=3)

        self.btn_run = ctk.CTkButton(sb, text="Run audit", height=42, font=ctk.CTkFont(size=15, weight="bold"), command=self.start)
        self.btn_run.pack(fill="x", padx=20, pady=(20, 6))
        row = ctk.CTkFrame(sb, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(14, 18))
        ctk.CTkLabel(row, text="Appearance").pack(side="left")
        self.mode_menu = ctk.CTkOptionMenu(row, values=["Dark", "Light", "System"], width=110, command=self._set_mode)
        self.mode_menu.pack(side="right")

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(side="left", fill="both", expand=True, padx=16, pady=14)
        head = ctk.CTkFrame(main, fg_color="transparent")
        head.pack(fill="x")
        self.title_lbl = ctk.CTkLabel(head, text="No audit yet", font=ctk.CTkFont(size=20, weight="bold"))
        self.title_lbl.pack(side="left")
        for kind in ("JSON", "CSV", "HTML"):
            ctk.CTkButton(head, text=f"Export {kind}", width=96, height=30, command=lambda k=kind.lower(): self.export(k), **OUTLINE).pack(side="right", padx=(6, 0))

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.pack(fill="x", pady=12)
        self.card = {}
        for i, (key, label, color) in enumerate((("n", "Checks run", None), ("FAIL", "Failed", STATUS_COLOR["FAIL"]), ("WARN", "Warnings", STATUS_COLOR["WARN"]),
                                                 ("PASS", "Passed", STATUS_COLOR["PASS"]), ("score", "Compliance score", None))):
            f = ctk.CTkFrame(cards, corner_radius=12)
            f.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="nsew")
            cards.grid_columnconfigure(i, weight=1, uniform="c")
            v = ctk.CTkLabel(f, text="-", font=ctk.CTkFont(size=30, weight="bold"), text_color=color or ("gray10", "gray95"))
            v.pack(anchor="w", padx=16, pady=(12, 0))
            ctk.CTkLabel(f, text=label, text_color=MUTED).pack(anchor="w", padx=16, pady=(0, 12))
            self.card[key] = v
        self.score_bar = ctk.CTkProgressBar(main, height=8)
        self.score_bar.set(0)
        self.score_bar.pack(fill="x", pady=(0, 10))

        self.tabs = ctk.CTkTabview(main, anchor="w")
        self.tabs.pack(fill="both", expand=True)
        t_find, t_area, t_log = (self.tabs.add(n) for n in ("Findings", "By area", "Log"))

        bar = ctk.CTkFrame(t_find, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 8))
        self.f_persp = ctk.CTkOptionMenu(bar, values=["ALL", "Admin", "User"], width=100, command=lambda _: self._refresh())
        self.f_area = ctk.CTkOptionMenu(bar, values=["ALL", *AREAS], width=120, command=lambda _: self._refresh())
        self.f_status = ctk.CTkOptionMenu(bar, values=["ALL", *STATUSES], width=100, command=lambda _: self._refresh())
        for w in (self.f_persp, self.f_area, self.f_status):
            w.pack(side="left", padx=(0, 8))
        self.f_entry = ctk.CTkEntry(bar, placeholder_text="Search team, site, check, value...", width=300)
        self.f_entry.pack(side="left")
        self.f_entry.bind("<KeyRelease>", lambda _e: self._refresh())
        self.count_lbl = ctk.CTkLabel(bar, text="", text_color=MUTED)
        self.count_lbl.pack(side="right")
        self.tree = self._make_tree(t_find, ("status", "view", "area", "check", "target", "actual"), (70, 70, 90, 330, 190, 330),
                                    ("Status", "View", "Area", "Check", "Target", "Actual"))
        self.tree.bind("<<TreeviewSelect>>", self._detail)
        self.detail = ctk.CTkTextbox(t_find, height=130, wrap="word", font=ctk.CTkFont(size=13))
        self.detail.pack(fill="x", pady=(8, 0))
        self.detail.configure(state="disabled")

        self.area_tree = self._make_tree(t_area, ("area", "view", "fail", "warn", "pass", "other"), (200, 120, 80, 80, 80, 80),
                                         ("Area", "View", "Fail", "Warn", "Pass", "Other"))
        self.area_tree.bind("<Double-1>", self._area_drill)
        ctk.CTkLabel(t_area, text="Admin = tenant configuration seen with the administrator sign-in. User = what a normal employee account "
                                  "can see or has configured. Double-click a row to see its findings.", text_color=MUTED, wraplength=900,
                     justify="left").pack(anchor="w", pady=(6, 0))
        self.log_box = ctk.CTkTextbox(t_log, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True)
        self.log_box.configure(state="disabled")

        self.status = ctk.CTkLabel(main, text="Ready. Passwords are typed on Microsoft's sign-in page, never here.", anchor="w", text_color=MUTED)
        self.status.pack(fill="x", pady=(8, 0))
        self.busy = ctk.CTkProgressBar(main, mode="indeterminate", height=4)

    def _make_tree(self, parent, cols, widths, heads):
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse", style="M365.Treeview")
        for c, w, h in zip(cols, widths, heads):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w", stretch=(c in ("actual", "check")))
        sb = ctk.CTkScrollbar(wrap, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tree

    # ------------------------------------------------------------------ theming
    def _style_tree(self):
        dark = ctk.get_appearance_mode() == "Dark"
        bg, fg, head = ("#242424", "#e6e6e6", "#2f2f2f") if dark else ("#ffffff", "#1a1a1a", "#eceef1")
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("M365.Treeview", background=bg, fieldbackground=bg, foreground=fg, rowheight=30, borderwidth=0, font=("Segoe UI", 10))
        st.configure("M365.Treeview.Heading", background=head, foreground=fg, relief="flat", font=("Segoe UI", 10, "bold"))
        st.map("M365.Treeview", background=[("selected", "#1f6aa5")], foreground=[("selected", "#ffffff")])
        st.map("M365.Treeview.Heading", background=[("active", head)])
        for s, col in (ROW_DARK if dark else ROW_LIGHT).items():
            self.tree.tag_configure(s, background=col)

    def _set_mode(self, mode):
        ctk.set_appearance_mode(mode)
        self.after(80, self._style_tree)

    # ------------------------------------------------------------------ sign-in
    def selected_areas(self):
        return tuple(a for a in AREAS if self.area_vars[a].get())

    def log(self, msg):
        self.q.put(("log", msg))

    def sign_in(self, persp):
        tenant, client = self.tenant.get().strip(), self.client.get().strip()
        areas = self.selected_areas()
        if not tenant or not client:
            messagebox.showwarning("Missing input", "Enter the tenant and the app (client) ID first.")
            return
        if not areas:
            messagebox.showwarning("No areas", "Select at least one area.")
            return
        if self.worker and self.worker.is_alive():
            return
        self._set_busy(True, f"Waiting for {persp.lower()} sign-in in your browser ...")

        def work():
            try:
                s = SignIn(persp, tenant, client)
                name = s.login(areas, device_code=bool(self.device.get()), show_code=lambda m: self.q.put(("code", m)))
                self.q.put(("signed", (persp, s, areas, name)))
            except Exception as e:
                self.q.put(("error", f"Sign-in failed: {e}"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    def sign_out(self, persp):
        self.sessions.pop(persp, None)
        self.chip[persp].configure(text="not signed in", text_color=MUTED)

    # ------------------------------------------------------------------ run
    def _set_busy(self, on, text=""):
        self.btn_run.configure(state="disabled" if on else "normal")
        if on:
            self.busy.pack(fill="x", pady=(4, 0))
            self.busy.start()
        else:
            self.busy.stop()
            self.busy.pack_forget()
        if text:
            self.status.configure(text=text)

    def start(self):
        areas = set(self.selected_areas())
        if not self.sessions:
            messagebox.showwarning("Not signed in", "Sign in as an administrator, an employee, or both.")
            return
        stale = [p for p, (_, signed) in self.sessions.items() if not areas <= set(signed)]
        if stale:
            messagebox.showwarning("Sign in again", "You selected areas that were not part of the sign-in consent for: " + ", ".join(stale) +
                                   ".\nSign in again so the needed read permissions are requested.")
            return
        if self.worker and self.worker.is_alive():
            return
        admin = self.sessions.get("Admin", (None,))[0]
        user = self.sessions.get("User", (None,))[0]
        opts = ScanOptions(tuple(a for a in AREAS if a in areas), bool(self.use_ps.get()), admin_upn=admin.name if admin else "")
        meta = {"tenant": (admin or user).tenant_id or self.tenant.get().strip()}
        self._set_busy(True, "Auditing ...")
        self.log("--- audit started ---")

        def work():
            try:
                self.q.put(("done", run_scan(Graph(admin.token) if admin else None, Graph(user.token) if user else None, opts, self.log, meta)))
            except Exception as e:
                self.q.put(("error", f"{type(e).__name__}: {e}"))
        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()

    # ------------------------------------------------------------------ results
    def load_results(self, results, meta):
        self.results, self.meta = results, meta
        c, score = gm.summary(results)
        self.title_lbl.configure(text=f"{meta.get('tenant', 'Audit')}  ·  {meta.get('perspectives', '')}")
        self.card["n"].configure(text=str(len(results)))
        for k in ("FAIL", "WARN", "PASS"):
            self.card[k].configure(text=str(c.get(k, 0)))
        self.card["score"].configure(text=f"{score}%", text_color=STATUS_COLOR["PASS"] if score >= 80 else STATUS_COLOR["WARN"] if score >= 50 else STATUS_COLOR["FAIL"])
        self.score_bar.set(score / 100)
        self._refresh()
        self.area_tree.delete(*self.area_tree.get_children())
        for r in gm.by_area(results):
            self.area_tree.insert("", "end", values=(r["area"], r["perspective"], r["fail"], r["warn"], r["pass"], r["other"]))

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        rows = gm.filter_results(self.results, self.f_status.get(), self.f_persp.get(), self.f_area.get(), self.f_entry.get())
        for r in rows:
            iid = self.tree.insert("", "end", values=(r.status, r.perspective, r.area, r.title, r.target, str(r.actual)[:160]), tags=(r.status,))
            self._rows[iid] = r
        self.count_lbl.configure(text=f"{len(rows)} of {len(self.results)} findings")
        self._style_tree()

    def _detail(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        r = self._rows[sel[0]]
        txt = (f"[{r.status}] {r.title}\nView: {r.perspective}    Area: {r.area}    Check: {r.check_id}    Target: {r.target or '-'}\n"
               f"Actual:   {r.actual}\nExpected: {r.expected}\n\nHow to fix:\n{r.remediation or 'Nothing to fix.'}")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", txt)
        self.detail.configure(state="disabled")

    def _area_drill(self, _evt=None):
        sel = self.area_tree.selection()
        if sel:
            area, persp = self.area_tree.item(sel[0], "values")[:2]
            self.f_area.set(area)
            self.f_persp.set(persp)
            self.f_status.set("ALL")
            self.tabs.set("Findings")
            self._refresh()

    def export(self, kind):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run an audit first.")
            return
        p = filedialog.asksaveasfilename(defaultextension="." + kind, initialfile=f"m365_audit.{kind}", filetypes=[(kind.upper(), "*." + kind)])
        if not p:
            return
        {"html": lambda: report.to_html(self.results, self.meta, p), "csv": lambda: report.to_csv(self.results, p),
         "json": lambda: report.to_json(self.results, self.meta, p)}[kind]()
        self.status.configure(text=f"Exported {p}")

    def _pump(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log_box.configure(state="normal")
                    self.log_box.insert("end", payload + "\n")
                    self.log_box.see("end")
                    self.log_box.configure(state="disabled")
                elif kind == "code":
                    self.log(payload)
                    messagebox.showinfo("Device-code sign-in", payload)
                elif kind == "signed":
                    persp, s, areas, name = payload
                    self.sessions[persp] = (s, frozenset(areas))
                    self.chip[persp].configure(text=name, text_color=STATUS_COLOR["PASS"])
                    self._set_busy(False, f"Signed in as {name} ({persp.lower()}).")
                elif kind == "done":
                    self._set_busy(False, f"Audit complete: {len(payload[0])} checks.")
                    self.load_results(*payload)
                elif kind == "error":
                    self._set_busy(False, "Failed - see Log tab.")
                    self.log(payload)
                    messagebox.showerror("Operation failed", payload)
        except queue.Empty:
            pass
        self.after(100, self._pump)


def main():
    App().mainloop()
