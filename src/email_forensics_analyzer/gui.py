import os
import sys
import csv
import json
import threading
import queue
import subprocess

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ModuleNotFoundError:  # common on minimal Linux installs
    tk = None
    ttk = None
    filedialog = None
    messagebox = None

# Analyzer
try:
    from .cli import analyze as analyze_func
except Exception:  # pragma: no cover
    analyze_func = None


def _missing_tk_message() -> str:
    return (
        "Tkinter is not available in this Python installation.\n\n"
        "On Debian/Kali, install it with:\n"
        "  sudo apt update && sudo apt install -y python3-tk\n"
    )


def _read_csv(path: str):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", newline="") as f:
        rdr = csv.DictReader(f)
        return list(rdr)


def _read_jsonl_headers(path: str):
    """Return dict message_tag -> headers dict."""
    if not os.path.exists(path):
        return {}
    out = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                tag = obj.get("message_tag")
                hdrs = obj.get("headers", {})
                if tag:
                    out[tag] = hdrs
            except json.JSONDecodeError:
                continue
    return out


def _open_path(path: str):
    if not path:
        return
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception as e:
        if messagebox:
            messagebox.showerror("Open failed", f"Could not open:\n{path}\n\n{e}")
        else:
            print(f"Could not open {path}: {e}", file=sys.stderr)


if tk is not None:
    class TableView(ttk.Frame):
        """
        Reusable table widget based on ttk.Treeview with:
        - Search filter
        - Column sorting
        - Row selection callback
        """
        def __init__(self, master, columns, on_select=None, height=14):
            super().__init__(master)
            self.columns = list(columns)
            self.on_select = on_select
            self._all_rows = []
            self._filtered_rows = []
            self._sort_state = {}  # col -> (ascending bool)

            # Search
            top = ttk.Frame(self)
            top.pack(fill="x", padx=8, pady=(8, 4))
            ttk.Label(top, text="Search:").pack(side="left")
            self.search_var = tk.StringVar()
            ent = ttk.Entry(top, textvariable=self.search_var)
            ent.pack(side="left", fill="x", expand=True, padx=(6, 0))
            ent.bind("<KeyRelease>", lambda e: self.apply_filter())

            # Tree
            self.tree = ttk.Treeview(self, columns=self.columns, show="headings", height=height)
            for c in self.columns:
                self.tree.heading(c, text=c, command=lambda col=c: self.sort_by(col))
                self.tree.column(c, width=max(90, min(260, len(c) * 10)), anchor="w")
            self.tree.bind("<<TreeviewSelect>>", self._handle_select)

            ysb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
            xsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
            self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)

            self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 0))
            ysb.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, anchor="ne")
            xsb.pack(fill="x", padx=8, pady=(0, 8))

        def set_rows(self, rows):
            self._all_rows = list(rows or [])
            self.apply_filter(reset_sort=True)

        def apply_filter(self, reset_sort=False):
            q = (self.search_var.get() or "").strip().lower()
            if q:
                self._filtered_rows = [
                    r for r in self._all_rows
                    if q in " ".join(str(r.get(c, "")) for c in self.columns).lower()
                ]
            else:
                self._filtered_rows = list(self._all_rows)

            if reset_sort:
                self._sort_state = {}

            self._render()

        def _render(self):
            self.tree.delete(*self.tree.get_children())
            for i, r in enumerate(self._filtered_rows):
                values = [r.get(c, "") for c in self.columns]
                self.tree.insert("", "end", iid=str(i), values=values)

        def sort_by(self, col):
            asc = self._sort_state.get(col, True)
            self._sort_state = {col: not asc}  # single-column sort

            def keyfunc(r):
                v = r.get(col, "")
                try:
                    return float(v)
                except Exception:
                    return str(v).lower()

            self._filtered_rows.sort(key=keyfunc, reverse=asc)
            self._render()

        def selected_row(self):
            sel = self.tree.selection()
            if not sel:
                return None
            try:
                idx = int(sel[0])
                return self._filtered_rows[idx]
            except Exception:
                return None

        def _handle_select(self, _event):
            if self.on_select:
                row = self.selected_row()
                if row is not None:
                    self.on_select(row)


    class EmailForensicsGUI(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Email Forensics Analyzer")
            self.geometry("1200x760")

            self.input_path = tk.StringVar()
            self.out_dir = tk.StringVar(value=os.path.abspath("out_gui"))
            self.filter_from = tk.StringVar()
            self.filter_subject = tk.StringVar()
            self.max_emails = tk.IntVar(value=0)

            self.current_message_tag = None
            self.data = {
                "emails": [],
                "spoofing": [],
                "headers": {},
                "interactions": [],
                "attachments": [],
                "campaigns": [],
            }
            self.attachments_by_tag = {}

            self.log_queue = queue.Queue()
            self._build_ui()
            self._poll_log_queue()

        def _build_ui(self):
            controls = ttk.Frame(self)
            controls.pack(fill="x", padx=10, pady=10)

            ttk.Label(controls, text="Input (MBOX/PST or folder):").grid(row=0, column=0, sticky="w")
            ttk.Entry(controls, textvariable=self.input_path, width=65).grid(row=0, column=1, sticky="we", padx=(6, 6))
            ttk.Button(controls, text="Browse File…", command=self._browse_file).grid(row=0, column=2, padx=(0, 6))
            ttk.Button(controls, text="Browse Folder…", command=self._browse_folder).grid(row=0, column=3)

            ttk.Label(controls, text="Output folder:").grid(row=1, column=0, sticky="w", pady=(8, 0))
            ttk.Entry(controls, textvariable=self.out_dir, width=65).grid(row=1, column=1, sticky="we", padx=(6, 6), pady=(8, 0))
            ttk.Button(controls, text="Choose…", command=self._choose_out).grid(row=1, column=2, pady=(8, 0), padx=(0, 6))
            ttk.Button(controls, text="Open Output", command=lambda: _open_path(self.out_dir.get())).grid(row=1, column=3, pady=(8, 0))

            opts = ttk.Frame(controls)
            opts.grid(row=2, column=0, columnspan=4, sticky="we", pady=(10, 0))
            ttk.Label(opts, text="Filter From:").grid(row=0, column=0, sticky="w")
            ttk.Entry(opts, textvariable=self.filter_from, width=28).grid(row=0, column=1, padx=(6, 14))
            ttk.Label(opts, text="Filter Subject:").grid(row=0, column=2, sticky="w")
            ttk.Entry(opts, textvariable=self.filter_subject, width=28).grid(row=0, column=3, padx=(6, 14))
            ttk.Label(opts, text="Max Emails (0=all):").grid(row=0, column=4, sticky="w")
            ttk.Entry(opts, textvariable=self.max_emails, width=8).grid(row=0, column=5, padx=(6, 14))

            self.run_btn = ttk.Button(opts, text="Run Analysis", command=self._run_analysis)
            self.run_btn.grid(row=0, column=6, padx=(0, 8))
            ttk.Button(opts, text="Load Existing Output", command=self._load_outputs).grid(row=0, column=7)

            controls.columnconfigure(1, weight=1)

            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

            self.tab_overview = ttk.Frame(self.nb)
            self.tab_emails = ttk.Frame(self.nb)
            self.tab_spoofing = ttk.Frame(self.nb)
            self.tab_headers = ttk.Frame(self.nb)
            self.tab_interactions = ttk.Frame(self.nb)
            self.tab_attachments = ttk.Frame(self.nb)
            self.tab_campaigns = ttk.Frame(self.nb)
            self.tab_log = ttk.Frame(self.nb)

            self.nb.add(self.tab_overview, text="Overview")
            self.nb.add(self.tab_emails, text="Emails")
            self.nb.add(self.tab_spoofing, text="Spoofing Indicators")
            self.nb.add(self.tab_headers, text="Headers")
            self.nb.add(self.tab_interactions, text="Interactions")
            self.nb.add(self.tab_attachments, text="Attachments")
            self.nb.add(self.tab_campaigns, text="Campaigns")
            self.nb.add(self.tab_log, text="Run Log")

            self._build_overview()
            self._build_emails()
            self._build_spoofing()
            self._build_headers()
            self._build_interactions()
            self._build_attachments()
            self._build_campaigns()
            self._build_log()

        def _build_overview(self):
            frm = ttk.Frame(self.tab_overview)
            frm.pack(fill="both", expand=True, padx=10, pady=10)

            self.ov_labels = {}
            grid = ttk.Frame(frm)
            grid.pack(anchor="nw", fill="x")

            def add_row(r, label):
                ttk.Label(grid, text=label).grid(row=r, column=0, sticky="w", pady=4)
                v = ttk.Label(grid, text="—", font=("TkDefaultFont", 10, "bold"))
                v.grid(row=r, column=1, sticky="w", padx=(10, 0), pady=4)
                self.ov_labels[label] = v

            add_row(0, "Emails analyzed")
            add_row(1, "High risk emails")
            add_row(2, "Medium risk emails")
            add_row(3, "Low risk emails")
            add_row(4, "Attachments extracted")
            add_row(5, "Unique senders")
            add_row(6, "Unique recipient addresses")

            ttk.Separator(frm, orient="horizontal").pack(fill="x", pady=12)

            bottom = ttk.Frame(frm)
            bottom.pack(fill="both", expand=True)

            self.top_senders = TableView(bottom, columns=["sender_email", "count"], height=10)
            self.top_senders.pack(side="left", fill="both", expand=True, padx=(0, 10))
            self.top_domains = TableView(bottom, columns=["sender_domain", "count"], height=10)
            self.top_domains.pack(side="left", fill="both", expand=True)

        def _build_emails(self):
            container = ttk.Frame(self.tab_emails)
            container.pack(fill="both", expand=True, padx=10, pady=10)

            left = ttk.Frame(container)
            left.pack(side="left", fill="both", expand=True)

            email_cols = [
                "message_tag", "date_iso", "sender_email", "to_raw", "subject",
                "message_id", "return_path", "reply_to"
            ]
            self.email_table = TableView(left, columns=email_cols, on_select=self._on_email_selected, height=18)
            self.email_table.pack(fill="both", expand=True)

            right = ttk.Frame(container)
            right.pack(side="left", fill="both", expand=False, padx=(10, 0))
            ttk.Label(right, text="Selected Email Details", font=("TkDefaultFont", 11, "bold")).pack(anchor="w")
            self.email_detail = tk.Text(right, width=55, height=28, wrap="word")
            self.email_detail.pack(fill="both", expand=True, pady=(6, 0))
            self.email_detail.configure(state="disabled")

        def _build_spoofing(self):
            frm = ttk.Frame(self.tab_spoofing)
            frm.pack(fill="both", expand=True, padx=10, pady=10)

            cols = [
                "message_tag", "date_iso", "sender_email", "sender_domain", "subject",
                "risk_score", "risk_level",
                "spf_suspicious", "dkim_suspicious", "dmarc_suspicious",
                "from_returnpath_mismatch", "replyto_domain_mismatch", "messageid_domain_mismatch",
                "few_received_hops", "name_impersonation_hint"
            ]
            self.spoof_table = TableView(frm, columns=cols, on_select=self._on_spoof_selected, height=14)
            self.spoof_table.pack(fill="both", expand=True)

            ttk.Label(frm, text="Indicator Details (selected row)", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(6, 0))
            self.spoof_detail = tk.Text(frm, height=7, wrap="word")
            self.spoof_detail.pack(fill="both", expand=False, pady=(6, 0))
            self.spoof_detail.configure(state="disabled")

        def _build_headers(self):
            container = ttk.Frame(self.tab_headers)
            container.pack(fill="both", expand=True, padx=10, pady=10)

            top = ttk.Frame(container)
            top.pack(fill="x")
            ttk.Label(top, text="Message Tag:").pack(side="left")
            self.hdr_tag_var = tk.StringVar(value="—")
            ttk.Label(top, textvariable=self.hdr_tag_var, font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(6, 0))
            ttk.Button(top, text="Copy Headers", command=self._copy_headers).pack(side="right")

            self.headers_text = tk.Text(container, wrap="none")
            self.headers_text.pack(fill="both", expand=True, pady=(8, 0))
            self.headers_text.configure(state="disabled")

        def _build_interactions(self):
            frm = ttk.Frame(self.tab_interactions)
            frm.pack(fill="both", expand=True, padx=10, pady=10)
            cols = ["sender", "recipient", "count", "first_seen", "last_seen"]
            self.inter_table = TableView(frm, columns=cols, height=18)
            self.inter_table.pack(fill="both", expand=True)

        def _build_attachments(self):
            container = ttk.Frame(self.tab_attachments)
            container.pack(fill="both", expand=True, padx=10, pady=10)

            top = ttk.Frame(container)
            top.pack(fill="x")
            ttk.Label(top, text="Message Tag:").pack(side="left")
            self.att_tag_var = tk.StringVar(value="—")
            ttk.Label(top, textvariable=self.att_tag_var, font=("TkDefaultFont", 10, "bold")).pack(side="left", padx=(6, 0))
            ttk.Button(top, text="Open attachments folder", command=self._open_selected_attachment_folder).pack(side="right")

            cols = ["message_tag", "filename", "path", "content_type", "size_bytes", "md5", "sha256"]
            self.att_table = TableView(container, columns=cols, on_select=self._on_attachment_selected, height=14)
            self.att_table.pack(fill="both", expand=True, pady=(8, 0))

            ttk.Label(container, text="Attachment Details (selected row)", font=("TkDefaultFont", 11, "bold")).pack(anchor="w", pady=(10, 0))
            self.att_detail = tk.Text(container, height=6, wrap="word")
            self.att_detail.pack(fill="both", expand=False, pady=(6, 0))
            self.att_detail.configure(state="disabled")

            bottom = ttk.Frame(container)
            bottom.pack(fill="x", pady=(8, 0))
            ttk.Button(bottom, text="Open selected attachment file", command=self._open_selected_attachment_file).pack(side="left")
            ttk.Button(bottom, text="Copy SHA-256", command=self._copy_selected_sha256).pack(side="left", padx=(8, 0))

        def _build_campaigns(self):
            frm = ttk.Frame(self.tab_campaigns)
            frm.pack(fill="both", expand=True, padx=10, pady=10)
            cols = ["subject_norm", "sender_domain", "count", "first_seen", "last_seen", "example_subject"]
            self.camp_table = TableView(frm, columns=cols, height=18)
            self.camp_table.pack(fill="both", expand=True)

        def _build_log(self):
            frm = ttk.Frame(self.tab_log)
            frm.pack(fill="both", expand=True, padx=10, pady=10)
            self.log_text = tk.Text(frm, wrap="word")
            self.log_text.pack(fill="both", expand=True)
            self.log_text.configure(state="disabled")

        def _browse_file(self):
            path = filedialog.askopenfilename(
                title="Select mailbox file",
                filetypes=[
                    ("Mailboxes", "*.mbox *.mbx *.pst"),
                    ("MBOX", "*.mbox *.mbx"),
                    ("PST", "*.pst"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                self.input_path.set(path)

        def _browse_folder(self):
            path = filedialog.askdirectory(title="Select folder containing mailbox files")
            if path:
                self.input_path.set(path)

        def _choose_out(self):
            path = filedialog.askdirectory(title="Select output folder")
            if path:
                self.out_dir.set(path)

        def _append_log(self, s: str):
            self.log_queue.put(s)

        def _poll_log_queue(self):
            try:
                while True:
                    s = self.log_queue.get_nowait()
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", s)
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
            except queue.Empty:
                pass
            self.after(200, self._poll_log_queue)

        def _run_analysis(self):
            in_path = (self.input_path.get() or "").strip()
            out_dir = (self.out_dir.get() or "").strip()
            if not in_path:
                messagebox.showwarning("Missing input", "Please select an input MBOX/PST file (or a folder).")
                return
            if not out_dir:
                messagebox.showwarning("Missing output", "Please choose an output folder.")
                return

            os.makedirs(out_dir, exist_ok=True)
            self.run_btn.configure(state="disabled")
            self._append_log(f"\n=== Running analysis ===\nInput: {in_path}\nOutput: {out_dir}\n\n")

            t = threading.Thread(target=self._analysis_worker, args=(in_path, out_dir), daemon=True)
            t.start()

        def _analysis_worker(self, in_path: str, out_dir: str):
            try:
                if analyze_func is not None:
                    analyze_func(
                        input_path=in_path,
                        out_dir=out_dir,
                        filter_from=self.filter_from.get().strip(),
                        filter_subject=self.filter_subject.get().strip(),
                        max_emails=int(self.max_emails.get() or 0),
                    )
                    self._append_log("\n[+] Analysis completed.\n")
                else:
                    cmd = [
                        sys.executable, "-m", "email_forensics_analyzer", "analyze",
                        "--input", in_path,
                        "--out", out_dir,
                        "--filter-from", self.filter_from.get().strip(),
                        "--filter-subject", self.filter_subject.get().strip(),
                        "--max-emails", str(int(self.max_emails.get() or 0)),
                    ]
                    env = os.environ.copy()
                    repo_src = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
                    env["PYTHONPATH"] = os.pathsep.join([repo_src, env.get("PYTHONPATH", "")])
                    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
                    self._append_log(proc.stdout + "\n" + proc.stderr + "\n")
                    if proc.returncode != 0:
                        raise RuntimeError(f"Analyzer failed (exit {proc.returncode}).")
            except Exception as e:
                self._append_log(f"\n[!] ERROR: {e}\n")
                self.after(0, lambda: messagebox.showerror("Analysis failed", str(e)))
            finally:
                self.after(0, self._on_analysis_done)

        def _on_analysis_done(self):
            self.run_btn.configure(state="normal")
            self._load_outputs()

        def _load_outputs(self):
            out_dir = (self.out_dir.get() or "").strip()
            if not out_dir or not os.path.exists(out_dir):
                messagebox.showwarning("Missing output", "Output folder does not exist.")
                return

            emails = _read_csv(os.path.join(out_dir, "emails.csv"))
            spoof = _read_csv(os.path.join(out_dir, "spoofing_report.csv"))
            inter = _read_csv(os.path.join(out_dir, "interactions.csv"))
            att = _read_csv(os.path.join(out_dir, "attachments_report.csv"))
            camps = _read_csv(os.path.join(out_dir, "campaigns.csv"))
            hdrs = _read_jsonl_headers(os.path.join(out_dir, "headers.jsonl"))

            self.data.update({
                "emails": emails,
                "spoofing": spoof,
                "headers": hdrs,
                "interactions": inter,
                "attachments": att,
                "campaigns": camps,
            })

            by_tag = {}
            for a in att:
                by_tag.setdefault(a.get("message_tag", ""), []).append(a)
            self.attachments_by_tag = by_tag

            self.email_table.set_rows(emails)
            self.spoof_table.set_rows(spoof)
            self.inter_table.set_rows(inter)
            self.att_table.set_rows(att)
            self.camp_table.set_rows(camps)

            self._refresh_overview()
            self._append_log(f"\n[+] Loaded output folder: {out_dir}\n")

            if emails:
                self._select_message_tag(emails[0].get("message_tag"))

        def _refresh_overview(self):
            emails = self.data.get("emails", [])
            spoof = self.data.get("spoofing", [])
            att = self.data.get("attachments", [])

            total_emails = len(emails)
            by_risk = {"high": 0, "medium": 0, "low": 0, "none": 0, "": 0}
            for s in spoof:
                key = str(s.get("risk_level", "")).lower()
                by_risk[key] = by_risk.get(key, 0) + 1

            senders = set()
            recipients = set()
            for e in emails:
                se = (e.get("sender_email") or "").strip()
                if se:
                    senders.add(se.lower())
                to = (e.get("to_raw") or "").strip()
                if to:
                    for part in to.replace(";", ",").split(","):
                        p = part.strip()
                        if p:
                            recipients.add(p.lower())

            def set_label(name, value):
                lbl = self.ov_labels.get(name)
                if lbl:
                    lbl.configure(text=str(value))

            set_label("Emails analyzed", total_emails)
            set_label("High risk emails", by_risk.get("high", 0))
            set_label("Medium risk emails", by_risk.get("medium", 0))
            set_label("Low risk emails", by_risk.get("low", 0))
            set_label("Attachments extracted", len(att))
            set_label("Unique senders", len(senders))
            set_label("Unique recipient addresses", len(recipients))

            sender_counts = {}
            domain_counts = {}
            for e in emails:
                se = (e.get("sender_email") or "").strip()
                sd = (e.get("sender_domain") or "").strip()
                if se:
                    sender_counts[se] = sender_counts.get(se, 0) + 1
                if sd:
                    domain_counts[sd] = domain_counts.get(sd, 0) + 1
            top_s = sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)[:25]
            top_d = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:25]
            self.top_senders.set_rows([{"sender_email": k, "count": v} for k, v in top_s])
            self.top_domains.set_rows([{"sender_domain": k, "count": v} for k, v in top_d])

        def _select_message_tag(self, message_tag: str):
            if not message_tag:
                return
            self.current_message_tag = message_tag
            self._update_email_detail(message_tag)
            self._update_spoof_detail(message_tag)
            self._update_headers_view(message_tag)
            self._update_attachments_view(message_tag)

        def _on_email_selected(self, row):
            self._select_message_tag(row.get("message_tag"))

        def _on_spoof_selected(self, row):
            self._select_message_tag(row.get("message_tag"))

        def _on_attachment_selected(self, row):
            self._set_text(self.att_detail, self._format_dict(row))

        def _update_email_detail(self, tag: str):
            row = next((r for r in self.data.get("emails", []) if r.get("message_tag") == tag), None)
            if not row:
                self._set_text(self.email_detail, "No email record found for selected message.")
                return

            risk = next((s for s in self.data.get("spoofing", []) if s.get("message_tag") == tag), None)
            lines = ["Core Fields", "----------"]
            for k in ["date_iso", "sender_email", "sender_domain", "to_raw", "cc_raw", "subject",
                      "message_id", "return_path", "reply_to", "source_mailbox"]:
                if k in row:
                    lines.append(f"{k}: {row.get(k, '')}")
            if risk:
                lines += ["", "Risk Summary", "-----------",
                          f"risk_level: {risk.get('risk_level', '')}",
                          f"risk_score: {risk.get('risk_score', '')}"]
            self._set_text(self.email_detail, "\n".join(lines))

        def _update_spoof_detail(self, tag: str):
            row = next((s for s in self.data.get("spoofing", []) if s.get("message_tag") == tag), None)
            if not row:
                self._set_text(self.spoof_detail, "No spoofing record found for selected message.")
                return

            lines = [f"risk_level={row.get('risk_level')}  risk_score={row.get('risk_score')}", ""]
            ind_keys = [
                "spf_suspicious", "dkim_suspicious", "dmarc_suspicious",
                "from_returnpath_mismatch", "replyto_domain_mismatch", "messageid_domain_mismatch",
                "few_received_hops", "name_impersonation_hint",
            ]
            lines.append("Indicators set:")
            for k in ind_keys:
                v = row.get(k, "")
                if str(v) in ("1", "True", "true", "yes"):
                    lines.append(f"  - {k}: YES")
            lines += ["", "Details:"]
            for k, v in row.items():
                if k.startswith("detail_") and v:
                    lines.append(f"  - {k}: {v}")
            self._set_text(self.spoof_detail, "\n".join(lines))

        def _update_headers_view(self, tag: str):
            hdrs = self.data.get("headers", {}).get(tag)
            self.hdr_tag_var.set(tag if tag else "—")
            if not hdrs:
                self._set_text(self.headers_text, "No headers found for selected message (headers.jsonl missing or message not indexed).")
                return
            lines = []
            for k in sorted(hdrs.keys(), key=lambda x: x.lower()):
                v = hdrs[k]
                if isinstance(v, list):
                    lines.append(f"{k}:")
                    for item in v:
                        lines.append(f"  - {item}")
                else:
                    lines.append(f"{k}: {v}")
            self._set_text(self.headers_text, "\n".join(lines))

        def _update_attachments_view(self, tag: str):
            self.att_tag_var.set(tag if tag else "—")
            self.att_table.set_rows(self.attachments_by_tag.get(tag, []))

        def _copy_headers(self):
            tag = self.current_message_tag
            if not tag:
                return
            txt = self.headers_text.get("1.0", "end").strip()
            if not txt:
                return
            self.clipboard_clear()
            self.clipboard_append(txt)
            messagebox.showinfo("Copied", "Headers copied to clipboard.")

        def _open_selected_attachment_folder(self):
            out_dir = (self.out_dir.get() or "").strip()
            tag = self.current_message_tag
            if not out_dir or not tag:
                return
            _open_path(os.path.join(out_dir, "attachments", tag))

        def _open_selected_attachment_file(self):
            row = self.att_table.selected_row()
            if not row:
                return
            out_dir = (self.out_dir.get() or "").strip()
            rel = row.get("path", "")
            p = rel
            if out_dir and rel and not os.path.isabs(rel):
                p = os.path.join(out_dir, rel)
            _open_path(p)

        def _copy_selected_sha256(self):
            row = self.att_table.selected_row()
            if not row:
                return
            sha = (row.get("sha256") or "").strip()
            if not sha:
                return
            self.clipboard_clear()
            self.clipboard_append(sha)
            messagebox.showinfo("Copied", "SHA-256 copied to clipboard.")

        @staticmethod
        def _format_dict(d):
            return "\n".join([f"{k}: {d.get(k)}" for k in sorted(d.keys(), key=lambda x: x.lower())])

        @staticmethod
        def _set_text(widget: tk.Text, s: str):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", s or "")
            widget.configure(state="disabled")


def main():
    if tk is None:
        print(_missing_tk_message(), file=sys.stderr)
        raise SystemExit(1)
    app = EmailForensicsGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
