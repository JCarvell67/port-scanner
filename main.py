# SECTION 1 - IMPORTS #

import csv
import json
import queue
import socket
import threading
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
import tkinter as tk


# SECTION 2 - CONSTANTS #

SERVICES = {
    20: "FTP-Data",    21: "FTP",         22: "SSH",         23: "Telnet",
    25: "SMTP",        53: "DNS",         67: "DHCP",        68: "DHCP",
    69: "TFTP",        80: "HTTP",        110: "POP3",       119: "NNTP",
    123: "NTP",        135: "RPC",        139: "NetBIOS",    143: "IMAP",
    161: "SNMP",       194: "IRC",        389: "LDAP",       443: "HTTPS",
    445: "SMB",        465: "SMTPS",      514: "Syslog",     587: "SMTP",
    636: "LDAPS",      993: "IMAPS",      995: "POP3S",      1433: "MSSQL",
    1521: "Oracle",    1723: "PPTP",      3306: "MySQL",     3389: "RDP",
    5432: "Postgres",  5900: "VNC",       5985: "WinRM",     6379: "Redis",
    8080: "HTTP-Alt",  8443: "HTTPS-Alt", 8888: "HTTP-Alt",  9200: "Elasticsearch",
    27017: "MongoDB",
}

BG_DARK   = "#1e1e2e"
BG_PANEL  = "#2a2a3e"
BG_CARD   = "#313244"
ACCENT    = "#a6e3a1"
BLUE      = "#89b4fa"
RED       = "#f38ba8"
YELLOW    = "#f9e2af"
TEXT      = "#cdd6f4"
TEXT_DIM  = "#6c7086"
BORDER    = "#45475a"


# SECTION 3 - SCANNER #

class Scanner:
    def __init__(self, host, start, end, threads, timeout, result_q, stop_event):
        self.host       = host
        self.start      = start
        self.end        = end
        self.threads    = threads
        self.timeout    = timeout
        self.result_q   = result_q
        self.stop_event = stop_event
        self._lock      = threading.Lock()
        self.scanned    = 0

    def run(self):
        sem     = threading.Semaphore(self.threads)
        workers = []

        for port in range(self.start, self.end + 1):
            if self.stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._check, args=(port, sem), daemon=True)
            t.start()
            workers.append(t)

        for w in workers:
            w.join()

        if not self.stop_event.is_set():
            self.result_q.put(("done", None))

    def _check(self, port, sem):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.host, port)) == 0:
                    service = SERVICES.get(port, "unknown")
                    self.result_q.put(("open", (port, service)))
        except Exception:
            pass
        finally:
            with self._lock:
                self.scanned += 1
            self.result_q.put(("tick", None))
            sem.release()


# SECTION 4 - APP #

class PortScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("port_scanner.py")
        self.configure(bg=BG_DARK)
        self.minsize(860, 580)

        self._apply_style()

        # State
        self.result_q   = queue.Queue()
        self.stop_event = threading.Event()
        self.scanner    = None
        self.total      = 0
        self.open_ports = []  # list of (port, service)
        self.last_scan  = {}  # metadata saved at scan start for export

        self._build_inputs()
        self._build_progress()
        self._build_body()
        self._poll()

    # SECTION 4.1 - STYLE

    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("default")

        style.configure(".",
            background=BG_DARK, foreground=TEXT,
            fieldbackground=BG_CARD, troughcolor=BG_PANEL,
            bordercolor=BORDER, font=("Consolas", 10),
        )
        style.configure("TFrame",      background=BG_DARK)
        style.configure("TLabel",      background=BG_DARK, foreground=TEXT)
        style.configure("Dim.TLabel",  background=BG_DARK, foreground=TEXT_DIM, font=("Consolas", 9))
        style.configure("TScrollbar",  background=BG_PANEL, troughcolor=BG_DARK)

        style.configure("Green.Horizontal.TProgressbar",
            troughcolor=BG_PANEL, background=BLUE,
            bordercolor=BG_DARK, thickness=4,
        )

        style.configure("Treeview",
            background=BG_PANEL, foreground=TEXT,
            fieldbackground=BG_PANEL, rowheight=20, font=("Consolas", 10),
        )
        style.configure("Treeview.Heading",
            background=BG_DARK, foreground=TEXT_DIM,
            relief="flat", font=("Consolas", 9, "bold"),
        )
        style.map("Treeview",
            background=[("selected", BLUE)],
            foreground=[("selected", BG_DARK)],
        )

    # SECTION 4.2 - INPUTS

    def _build_inputs(self):
        hdr = tk.Frame(self, bg=BG_PANEL, pady=10)
        hdr.pack(fill="x")

        tk.Label(hdr, text="port_scanner.py", bg=BG_PANEL, fg=ACCENT,
                 font=("Consolas", 14, "bold")).pack(side="left", padx=16)

        self.state_var = tk.StringVar(value="idle")
        tk.Label(hdr, textvariable=self.state_var, bg=BG_PANEL, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(side="right", padx=16)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        inp = tk.Frame(self, bg=BG_DARK, padx=16, pady=12)
        inp.pack(fill="x")

        entry_cfg = dict(bg=BG_PANEL, fg=TEXT, insertbackground=ACCENT,
                         relief="flat", font=("Consolas", 10),
                         highlightthickness=1, highlightcolor=BLUE,
                         highlightbackground=BORDER)

        # Host
        host_wrap = tk.Frame(inp, bg=BG_DARK)
        host_wrap.pack(side="left", padx=(0, 14))
        tk.Label(host_wrap, text="host", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w")
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(host_wrap, textvariable=self.host_var, width=22,
                 **entry_cfg).pack(ipady=4, padx=1, pady=1)

        # Start port
        start_wrap = tk.Frame(inp, bg=BG_DARK)
        start_wrap.pack(side="left", padx=(0, 14))
        tk.Label(start_wrap, text="start port", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w")
        self.start_var = tk.StringVar(value="1")
        tk.Entry(start_wrap, textvariable=self.start_var, width=7,
                 **entry_cfg).pack(ipady=4, padx=1, pady=1)

        # End port
        end_wrap = tk.Frame(inp, bg=BG_DARK)
        end_wrap.pack(side="left", padx=(0, 14))
        tk.Label(end_wrap, text="end port", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w")
        self.end_var = tk.StringVar(value="1024")
        tk.Entry(end_wrap, textvariable=self.end_var, width=7,
                 **entry_cfg).pack(ipady=4, padx=1, pady=1)

        # Threads
        threads_wrap = tk.Frame(inp, bg=BG_DARK)
        threads_wrap.pack(side="left", padx=(0, 14))
        tk.Label(threads_wrap, text="threads", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w")
        self.threads_var = tk.StringVar(value="150")
        tk.Entry(threads_wrap, textvariable=self.threads_var, width=6,
                 **entry_cfg).pack(ipady=4, padx=1, pady=1)

        # Timeout
        timeout_wrap = tk.Frame(inp, bg=BG_DARK)
        timeout_wrap.pack(side="left", padx=(0, 14))
        tk.Label(timeout_wrap, text="timeout (s)", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w")
        self.timeout_var = tk.StringVar(value="0.5")
        tk.Entry(timeout_wrap, textvariable=self.timeout_var, width=6,
                 **entry_cfg).pack(ipady=4, padx=1, pady=1)

        # Buttons
        btn_cfg = dict(relief="flat", font=("Consolas", 10), cursor="hand2", pady=5, padx=14)

        self.scan_btn = tk.Button(inp, text="scan", command=self.start_scan,
                                  bg=ACCENT, fg=BG_DARK,
                                  activebackground="#88d4a0", activeforeground=BG_DARK,
                                  **btn_cfg)
        self.scan_btn.pack(side="left", padx=(10, 6))

        self.stop_btn = tk.Button(inp, text="stop", command=self.stop_scan,
                                  bg=BG_PANEL, fg=RED, state="disabled",
                                  activebackground=BORDER, activeforeground=RED,
                                  **btn_cfg)
        self.stop_btn.pack(side="left")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    # SECTION 4.3 - PROGRESS BAR

    def _build_progress(self):
        prog_row = tk.Frame(self, bg=BG_DARK, padx=16, pady=6)
        prog_row.pack(fill="x")

        self.prog_text = tk.Label(prog_row, text="0 / 0", bg=BG_DARK, fg=TEXT_DIM,
                                  font=("Consolas", 9))
        self.prog_text.pack(side="left")

        self.pct_text = tk.Label(prog_row, text="", bg=BG_DARK, fg=BLUE,
                                 font=("Consolas", 9))
        self.pct_text.pack(side="right")

        self.progress = ttk.Progressbar(prog_row, style="Green.Horizontal.TProgressbar",
                                        mode="determinate")
        self.progress.pack(fill="x", expand=True, side="left", padx=(10, 10))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

    # SECTION 4.4 - BODY

    def _build_body(self):
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        # Output log
        log_wrap = tk.Frame(body, bg=BG_DARK)
        log_wrap.pack(side="left", fill="both", expand=True)

        tk.Label(log_wrap, text="output", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(anchor="w", pady=(0, 4))

        self.log = scrolledtext.ScrolledText(
            log_wrap, bg=BG_PANEL, fg=TEXT, font=("Consolas", 10),
            relief="flat", wrap="word", state="disabled",
            highlightthickness=1, highlightbackground=BORDER,
            insertbackground=ACCENT,
        )
        self.log.pack(fill="both", expand=True)
        self.log.tag_configure("open", foreground=ACCENT)
        self.log.tag_configure("info", foreground=BLUE)
        self.log.tag_configure("warn", foreground=YELLOW)
        self.log.tag_configure("dim",  foreground=TEXT_DIM)

        # Results panel
        res_wrap = tk.Frame(body, bg=BG_DARK, padx=12)
        res_wrap.pack(side="right", fill="both")

        res_header = tk.Frame(res_wrap, bg=BG_DARK)
        res_header.pack(fill="x", pady=(0, 4))

        tk.Label(res_header, text="open ports", bg=BG_DARK, fg=TEXT_DIM,
                 font=("Consolas", 9)).pack(side="left")

        self.save_btn = tk.Button(res_header, text="save", command=self.export_results,
                                  bg=BG_PANEL, fg=BLUE, state="disabled",
                                  relief="flat", font=("Consolas", 9), padx=8, pady=2,
                                  cursor="hand2", activebackground=BORDER,
                                  activeforeground=BLUE)
        self.save_btn.pack(side="right")

        tbl_frame = tk.Frame(res_wrap, bg=BG_PANEL,
                             highlightthickness=1, highlightbackground=BORDER)
        tbl_frame.pack(fill="both", expand=True)

        vsb = tk.Scrollbar(tbl_frame, bg=BG_PANEL, troughcolor=BG_DARK, relief="flat")
        vsb.pack(side="right", fill="y")

        self.tree = ttk.Treeview(tbl_frame, columns=("port", "service"),
                                 show="headings",
                                 yscrollcommand=vsb.set)
        self.tree.heading("port",    text="port")
        self.tree.heading("service", text="service")
        self.tree.column("port",    width=65,  anchor="center")
        self.tree.column("service", width=130, anchor="w")
        self.tree.pack(fill="both", expand=True)
        vsb.config(command=self.tree.yview)

    # SECTION 4.5 - SCAN CONTROL

    def start_scan(self):
        host = self.host_var.get().strip()

        try:
            p1      = int(self.start_var.get())
            p2      = int(self.end_var.get())
            threads = int(self.threads_var.get())
            timeout = float(self.timeout_var.get())
        except ValueError:
            messagebox.showerror("bad input", "ports, threads, and timeout must be numbers")
            return

        if not host:
            messagebox.showerror("bad input", "host can't be empty")
            return
        if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535):
            messagebox.showerror("bad input", "ports must be 1-65535")
            return
        if p1 > p2:
            messagebox.showerror("bad input", "start port must be <= end port")
            return
        if not (1 <= threads <= 1000):
            messagebox.showerror("bad input", "threads must be 1-1000")
            return

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            messagebox.showerror("dns error", f"couldn't resolve: {host}")
            return

        # Reset
        self.stop_event.clear()
        self.open_ports.clear()
        self.total = p2 - p1 + 1

        self.progress["value"] = 0
        self.prog_text.config(text=f"0 / {self.total:,}")
        self.pct_text.config(text="")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        for row in self.tree.get_children():
            self.tree.delete(row)

        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.save_btn.config(state="disabled")
        self.state_var.set("scanning")

        self.last_scan = {
            "host":       host,
            "ip":         ip,
            "port_range": [p1, p2],
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
        }

        self.log_write(f"target:   {host} ({ip})", "info")
        self.log_write(f"range:    {p1}-{p2} ({self.total:,} ports)", "info")
        self.log_write(f"threads:  {threads}    timeout: {timeout}s", "dim")
        self.log_write("-" * 40, "dim")

        self.scanner = Scanner(ip, p1, p2, threads, timeout, self.result_q, self.stop_event)
        threading.Thread(target=self.scanner.run, daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.log_write("stopped by user", "warn")
        self.state_var.set("stopped")
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    # SECTION 4.6 - EXPORT

    def export_results(self):
        if not self.open_ports:
            messagebox.showinfo("nothing to save", "no open ports to export")
            return

        path = filedialog.asksaveasfilename(
            title="save results",
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json"),
                ("CSV",  "*.csv"),
                ("Text", "*.txt"),
            ],
        )
        if not path:
            return

        try:
            if path.endswith(".json"):
                self._save_json(path)
            elif path.endswith(".csv"):
                self._save_csv(path)
            else:
                self._save_txt(path)
            self.log_write(f"saved to {path}", "info")
        except Exception as e:
            messagebox.showerror("save failed", str(e))

    def _save_json(self, path):
        data = {
            **self.last_scan,
            "open_ports": [{"port": p, "service": s} for p, s in self.open_ports],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _save_csv(self, path):
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["port", "service", "host", "ip", "scanned_at"])
            for port, service in self.open_ports:
                writer.writerow([
                    port, service,
                    self.last_scan.get("host", ""),
                    self.last_scan.get("ip", ""),
                    self.last_scan.get("scanned_at", ""),
                ])

    def _save_txt(self, path):
        with open(path, "w") as f:
            f.write(f"host:       {self.last_scan.get('host', '')}\n")
            f.write(f"ip:         {self.last_scan.get('ip', '')}\n")
            f.write(f"port range: {self.last_scan.get('port_range', [])}\n")
            f.write(f"scanned at: {self.last_scan.get('scanned_at', '')}\n")
            f.write(f"open ports: {len(self.open_ports)}\n")
            f.write("-" * 30 + "\n")
            for port, service in self.open_ports:
                f.write(f"{port:<8} {service}\n")

    # SECTION 4.7 - QUEUE POLLING

    def _poll(self):
        try:
            while True:
                kind, data = self.result_q.get_nowait()

                if kind == "open":
                    port, service = data
                    self.open_ports.append((port, service))
                    self.log_write(f"open  {port:<6} {service}", "open")
                    self.tree.insert("", "end", values=(port, service))

                elif kind == "tick":
                    if self.scanner and self.total:
                        n   = self.scanner.scanned
                        pct = int(100 * n / self.total)
                        self.progress["value"] = pct
                        self.prog_text.config(text=f"{n:,} / {self.total:,}")
                        self.pct_text.config(text=f"{pct}%")

                elif kind == "done":
                    self._on_scan_done()

        except queue.Empty:
            pass

        self.after(40, self._poll)

    def _on_scan_done(self):
        n = len(self.open_ports)
        self.log_write("-" * 40, "dim")
        self.log_write(f"done. {n} open port{'s' if n != 1 else ''} found.", "info")
        self.progress["value"] = 100
        self.pct_text.config(text="100%")
        self.state_var.set("done")
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.open_ports:
            self.save_btn.config(state="normal")

    # SECTION 4.8 - HELPERS

    def log_write(self, msg, tag=""):
        self.log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")


# SECTION 5 - ENTRY POINT #

def main():
    app = PortScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()