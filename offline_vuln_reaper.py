# codeinecasket
import sys
import os
import csv
import zipfile
import argparse
import re
import io
import threading
import subprocess
import platform
import webbrowser
import tkinter as tk
import json 
from tkinter import filedialog, ttk, messagebox, Menu
from PIL import Image, ImageTk


KB_REGEX = re.compile(r'KB\d+', re.IGNORECASE)

WIN_MAP = {
    # Windows 10
    10240: "1507", 10586: "1511", 14393: "1607", 15063: "1703",
    16299: "1709", 17134: "1803", 17763: "1809", 18362: "1903",
    18363: "1909", 19041: "2004", 19042: "20H2", 19043: "21H1",
    19044: "21H2", 19045: "22H2",
    
    # Windows 11
    22000: "21H2",                  # Win11 Release
    22621: "22H2",                  # Win11 2022 Update
    22631: "23H2",                  # Win11 2023 Update (Moment 4)
    26100: "24H2",                  # Win11 2024 Update (IoT/LTSC)
    
    # Insider / Future / Canary Mappings (Mapping to nearest stable base for safety)
    23000: "22H2", 23600: "23H2",   # Dev/Beta 23H2 ranges
    25000: "24H2", 25398: "24H2",   # Server 2025 / Azure Stack
    26050: "24H2", 26080: "24H2",
    26200: "24H2",                  # Canary current
}

def load_external_versions():
    """Checks for versions.json to update WIN_MAP dynamically."""
    fpath = "versions.json"
    if os.path.exists(fpath):
        try:
            with open(fpath, "r") as f:
                new_map = json.load(f)
                info = {int(k): v for k, v in new_map.items()}
                WIN_MAP.update(info)
        except: pass


load_external_versions()

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class CoreScanner:
    def __init__(self):
        self.logger = print 
        self.db_filename = "definitions.zip"

    def set_logger(self, func):
        self.logger = func

    def _log(self, text):
        self.logger(text)

    def get_local_info(self):
        self._log("[*] Querying system info...")
        data = {}
        try:
            # 1. Basic System Info (OS, Build)
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            raw_si = subprocess.check_output("systeminfo", startupinfo=si, encoding='oem', errors='ignore')
            data['sysinfo'] = raw_si
            
            # 2. WMIC for reliable Hotfixes
            self._log("[*] Querying reliable patch list (WMIC)...")
            raw_wmic = subprocess.check_output("wmic qfe get HotFixID", startupinfo=si, encoding='oem', errors='ignore')
            data['hotfixes'] = raw_wmic
            
            # 3. Service Status for Config Analysis
            self._log("[*] Checking service configurations...")
            raw_sc = subprocess.check_output("sc query state= all", startupinfo=si, encoding='oem', errors='ignore')
            data['services'] = raw_sc
            
            return data
        except Exception as err:
            self._log(f"[-] Data collection failed: {err}")
            return None

    def load_defs(self):
        self._log("[*] Loading definition database from local file...")
        db_path = resource_path(self.db_filename)
        
        if not os.path.exists(db_path):
            self._log(f"[-] Database file not found: {db_path}")
            self._log("[-] Please ensure 'definitions.zip' is in the same directory.")
            return None
            
        try:
            with zipfile.ZipFile(db_path, 'r') as z:
                target = next((n for n in z.namelist() if n.endswith('.csv')), None)
                if not target:
                    self._log("[-] CSV not found in archive.")
                    return None
                    
                with z.open(target) as zf:
                    text_file = io.TextIOWrapper(zf, encoding='utf-8', errors='ignore')
                    r = csv.DictReader(text_file)
                    storage = [i for i in r]
                    
            self._log(f"[+] Database loaded successfully! ({len(storage)} definitions)")
            return storage
        except Exception as ex:
            self._log(f"[-] Load Error: {ex}")
            return None

    def parse_sys_output(self, raw_dict):
        raw_si = ""
        raw_qfe = "" 
        
        if isinstance(raw_dict, dict):
            raw_si = raw_dict.get('sysinfo', "")
            raw_qfe = raw_dict.get('hotfixes', "")
        else:
            raw_si = raw_dict 
            
        d = {'os': '', 'ver': '', 'build': 0, 'arch': '', 'fixes': set()}
        
        try:
            lines = [line.strip() for line in raw_si.splitlines() if line.strip()]
            for line in lines:
                lower = line.lower()
                if "os name" in lower and not d['os']:
                    val = ""
                    if ":" in line: val = line.split(":", 1)[1]
                    elif "\t" in line: val = line.split("\t")[-1]
                    else: val = re.sub(r'(?i)os name\s*[:\.]?\s*', '', line)
                    d['os'] = val.strip()

                if "os version" in lower and not d['ver']:
                    val = ""
                    if ":" in line: val = line.split(":", 1)[1]
                    elif "\t" in line: val = line.split("\t")[-1]
                    else: val = re.sub(r'(?i)os version\s*[:\.]?\s*', '', line)
                    d['ver'] = val.strip()
                    mb = re.search(r'Build (\d+)', val, re.IGNORECASE)
                    if mb: d['build'] = int(mb.group(1))
                    else:
                        chnks = val.split()[0].split('.')
                        if len(chnks) >= 3: 
                            try: d['build'] = int(chnks[2])
                            except: pass

                if "system type" in lower and not d['arch']:
                    d['arch'] = "x64" if "x64" in lower else ("x86" if "x86" in lower else "x64")

            if raw_qfe:
                d['fixes'].update(KB_REGEX.findall(raw_qfe))
            
            d['fixes'].update(KB_REGEX.findall(raw_si))
            
            if not d['os']:
                if "microsoft windows" in raw_si.lower()[:300]:
                    d['os'] = "Microsoft Windows 10/11 (Fallback)"
                else:
                    self._log("[-] Error: Could not determine OS.")
                    return None
            return d
        except Exception as ex:
            self._log(f"[-] Parse error: {ex}")
            return None

    def analyze(self, sys_data, db_list, services_blob=""):
        self._log(f"[*] Target: {sys_data['os']} (Build {sys_data['build']})")
        
        oname = sys_data['os'].lower().replace("microsoft ", "").replace("  ", " ")
        bnum = sys_data['build']
        arch = sys_data['arch']
        vtag = WIN_MAP.get(bnum, "")
        
        w11 = "windows 11" in oname
        w10 = "windows 10" in oname and not w11

        installed = {x.upper() for x in sys_data['fixes']}
        
        latest_patch_date = 0
        for item in db_list:
            kb = "KB" + item.get('BulletinKB', '')
            if kb in installed:
                raw_date = item.get('DatePosted', '')
                if raw_date and len(raw_date) == 8:
                    try:
                        idate = int(raw_date)
                        if idate > latest_patch_date: latest_patch_date = idate
                    except: pass
        
        self._log(f"[*] Latest Patch Date Found: {latest_patch_date}")

        mitigated_services = []
        if services_blob:
            if "Spooler" in services_blob and "RUNNING" not in services_blob.split("Spooler")[1][:50]:
                mitigated_services.append("print spooler")
            if "W3SVC" in services_blob and "RUNNING" not in services_blob.split("W3SVC")[1][:50]:
                mitigated_services.append("iis")
        
        detected = []
        
        for item in db_list:
            prod = item['AffectedProduct'].lower()
            
            if w11 and "windows 11" not in prod: continue
            elif w10 and "windows 10" not in prod: continue
            if arch == "x64" and ("32-bit" in prod or "x86" in prod): continue
            if arch == "x86" and ("x64" in prod or "itanium" in prod): continue

            if vtag:
                if "version " in prod:
                     mpv = re.search(r'version (\w+)', prod)
                     if mpv and mpv.group(1) != vtag: continue
                else: continue 
            
            # Filter by KB if present
            bid = item.get('BulletinKB', '')
            if not bid or ("KB" + bid) in installed: continue
            
            is_mitigated = False
            title_lower = item.get('Title', '').lower()
            for ms in mitigated_services:
                if ms in title_lower or ms in prod:
                    is_mitigated = True
                    break
            if is_mitigated: 
                continue 

            item['Status'] = 'Active'
            vuln_date = item.get('DatePosted', '')
            if vuln_date and len(vuln_date) == 8 and latest_patch_date > 0:
                if int(vuln_date) < latest_patch_date:
                    if "windows 10" in prod or "windows 11" in prod:
                         item['Status'] = 'Superseded?'

            detected.append(item)

        final_list = []
        seen = set()
        for v in detected:
            k = v.get('CVE', '') or v.get('Title', '')
            if k not in seen:
                seen.add(k)
                final_list.append(v)

        return final_list

class AppWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Offline Vuln-Reaper")
        self.master.geometry("1400x900")
        self.master.configure(bg="#0F1115") 
        
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1) 
        except: pass
        
        # Load Assets
        self.icon_img = None
        
        logo_path = resource_path("app_logo.png")
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path)
                img_resized = img.resize((64, 64), Image.Resampling.LANCZOS)
                self.icon_img = ImageTk.PhotoImage(img_resized)
                self.master.iconphoto(False, self.icon_img)
            except Exception as e:
                print(f"Icon load error: {e}")


        self.core = CoreScanner()

        self.core.set_logger(self.log_msg)
        self.full_dataset = [] 
        
        self.colors = {
            "bg": "#0F1115",
            "fg": "#E0E6ED",
            "panel": "#181B21", 
            "input": "#21252B", 
            "accent": "#00CED1", 
            "accent_hover": "#00B4B7",
            "text_dim": "#78828C",
            "danger": "#FF4444"
        }
        
        self.design()
        self.build_ui()
        
        # Start ephemeral load immediately
        threading.Thread(target=self.load_db_on_start, daemon=True).start()

    def load_db_on_start(self):
        self.core_db = self.core.load_defs()
        if not self.core_db:
            self.log_msg("! Data load failed. Ensure definitions.zip is present.")

    def design(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure(".", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 10))
        s.configure("Treeview", background=self.colors["panel"], foreground="#E0E6ED", fieldbackground=self.colors["panel"], rowheight=34, borderwidth=0, font=("Consolas", 10))
        s.configure("Treeview.Heading", background="#21252B", foreground=self.colors["accent"], font=("Segoe UI", 10, "bold"), borderwidth=0, relief="flat")
        s.map("Treeview", background=[('selected', "#2C313A")], foreground=[('selected', self.colors["accent"])])
        s.configure("TButton", font=("Segoe UI", 10, "bold"), background=self.colors["input"], foreground=self.colors["fg"], borderwidth=0, focuscolor=self.colors["input"], padding=8)
        s.map("TButton", background=[('active', "#323842"), ('pressed', "#21252B")], foreground=[('active', "white")])
        s.configure("Accent.TButton", background=self.colors["accent"], foreground="#0F1115")
        s.map("Accent.TButton", background=[('active', self.colors["accent_hover"]), ('pressed', self.colors["accent"])], foreground=[('active', "black")])
        s.configure("Warn.TButton", foreground=self.colors["danger"], background=self.colors["input"])
        s.map("Warn.TButton", background=[('active', "#323842")])
        s.configure("TEntry", fieldbackground=self.colors["input"], foreground="white", insertcolor="white", borderwidth=0)
        s.configure("TRadiobutton", background=self.colors["bg"], foreground=self.colors["fg"], indicatorcolor=self.colors["input"], padding=5)
        s.map("TRadiobutton", indicatorcolor=[('selected', self.colors["accent"])], background=[('active', self.colors["bg"]), ('pressed', self.colors["bg"])], foreground=[('active', self.colors["accent"])])

    def build_ui(self):
        top_bar = tk.Frame(self.master, padx=25, pady=25, bg=self.colors["bg"])
        top_bar.pack(fill=tk.X)
        
        # Header
        head_box = tk.Frame(top_bar, bg=self.colors["bg"])
        head_box.pack(side=tk.LEFT)
        tk.Label(head_box, text="OFFLINE REAPER", font=("Consolas", 14, "bold"), bg=self.colors["bg"], fg=self.colors["accent"]).pack(anchor="w")
        tk.Label(head_box, text="by codeinecasket", font=("Segoe UI", 9, "bold"), bg=self.colors["bg"], fg=self.colors["text_dim"]).pack(anchor="w")

        ctl_box = tk.Frame(top_bar, bg=self.colors["bg"], padx=40)
        ctl_box.pack(side=tk.LEFT, fill=tk.Y)
        
        self.s_mode = tk.StringVar(value="local")
        ttk.Radiobutton(ctl_box, text="LOCAL AUDIT", variable=self.s_mode, value="local", command=self.switch_input).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(ctl_box, text="FILE AUDIT", variable=self.s_mode, value="file", command=self.switch_input).pack(side=tk.LEFT, padx=10)
        
        self.file_frame = tk.Frame(top_bar, bg=self.colors["bg"])
        self.txt_path = ttk.Entry(self.file_frame, width=35)
        self.txt_path.pack(side=tk.LEFT, padx=5)
        ttk.Button(self.file_frame, text="BROWSE", command=self.find_file, width=10).pack(side=tk.LEFT)

        act_box = tk.Frame(top_bar, bg=self.colors["bg"])
        act_box.pack(side=tk.RIGHT)
        
        self.btn_go = ttk.Button(act_box, text="START SCAN", style="Accent.TButton", command=self.execute_scan)
        self.btn_go.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(act_box, text="RESET", style="Warn.TButton", command=self.reset_all, width=8).pack(side=tk.RIGHT, padx=5)
        ttk.Button(act_box, text="REPORT", command=self.generate_html_report, width=10).pack(side=tk.RIGHT, padx=5)
        ttk.Button(act_box, text="EXPORT DATA", command=self.save_results, width=15).pack(side=tk.RIGHT, padx=5)
        # Removed Update DB button as it is offline tool

        filter_bar = tk.Frame(self.master, bg=self.colors["bg"], padx=25, pady=5)
        filter_bar.pack(fill=tk.X)
        
        tk.Label(filter_bar, text="FILTER:", font=("Segoe UI", 9, "bold"), bg=self.colors["bg"], fg=self.colors["text_dim"]).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_results)
        ttk.Entry(filter_bar, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=10)
        
        self.show_superseded = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(filter_bar, text="Show Superseded / Historical Vulnerabilities", variable=self.show_superseded, 
                             command=self.filter_results, bg=self.colors["bg"], fg=self.colors["fg"], 
                             selectcolor=self.colors["bg"], activebackground=self.colors["bg"], activeforeground=self.colors["accent"])
        chk.pack(side=tk.LEFT, padx=20)

        grid_frame = tk.Frame(self.master, bg=self.colors["bg"], padx=25, pady=10)
        grid_frame.pack(fill=tk.BOTH, expand=True)
        
        inner_frame = tk.Frame(grid_frame, bg=self.colors["panel"], padx=1, pady=1)
        inner_frame.pack(fill=tk.BOTH, expand=True)
        
        cols = ("sev", "cve", "kb", "status", "title")
        self.grid = ttk.Treeview(inner_frame, columns=cols, show='headings', selectmode="extended")
        
        scroller = ttk.Scrollbar(inner_frame, orient="vertical", command=self.grid.yview)
        scroller.pack(side=tk.RIGHT, fill=tk.Y)
        self.grid.configure(yscroll=scroller.set)
        self.grid.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.grid.heading("sev", text="SEVERITY", command=lambda: self.sort_table("sev", False))
        self.grid.heading("cve", text="CVE ID", command=lambda: self.sort_table("cve", False))
        self.grid.heading("kb", text="KB ID", command=lambda: self.sort_table("kb", False))
        self.grid.heading("status", text="STATUS", command=lambda: self.sort_table("status", False))
        self.grid.heading("title", text="VULNERABILITY", command=lambda: self.sort_table("title", False))
        
        self.grid.column("sev", width=100, anchor="center")
        self.grid.column("cve", width=140, anchor="center")
        self.grid.column("kb", width=100, anchor="center")
        self.grid.column("status", width=120, anchor="center")
        self.grid.column("title", width=700)

        self.grid.tag_configure('Critical', foreground='#FF5555', font=('Consolas', 10, 'bold')) 
        self.grid.tag_configure('Important', foreground='#FFB86C', font=('Consolas', 10))       
        self.grid.tag_configure('Moderate', foreground='#F1FA8C', font=('Consolas', 10))        
        self.grid.tag_configure('Superseded?', foreground='#6272A4', font=('Consolas', 10, 'italic')) 

        self.pops = Menu(self.master, tearoff=0, bg=self.colors["input"], fg="white", activebackground=self.colors["accent"], activeforeground="black")
        self.pops.add_command(label="Copy Row (Markdown)", command=self.copy_markdown)
        self.pops.add_command(label="Copy Details (Text)", command=self.copy_lines)
        self.pops.add_command(label="Open NIST Page", command=self.launch_url)
        self.grid.bind("<Button-3>", self.show_pops)

        log_frame = tk.LabelFrame(self.master, text="AUDIT LOGS", bg=self.colors["bg"], fg=self.colors["text_dim"], font=("Segoe UI", 9, "bold"), bd=0)
        log_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=25, pady=10)
        
        self.log_area = tk.Text(log_frame, height=5, bg=self.colors["input"], fg="#98C379", font=("Consolas", 9), blockcursor=True, state='disabled', bd=0, padx=5, pady=5)
        self.log_area.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        log_scr = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_area.yview)
        log_scr.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_area.configure(yscroll=log_scr.set)
        
        self.switch_input()
        self.log_msg("Engine Initialized. Loading local database...")
    
    def html_template(self):
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Offline Security Assessment Report</title>
            <style>
                body { font-family: 'Segoe UI', sans-serif; background: #0F1115; color: #E0E6ED; padding: 40px; }
                h1 { color: #00CED1; }
                .summary { background: #181B21; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #181B21; border-radius: 8px; overflow: hidden; }
                th, td { text-align: left; padding: 15px; border-bottom: 1px solid #2C313A; }
                th { color: #00CED1; font-weight: 600; cursor: pointer; user-select: none; background: #21252B; }
                th:hover { background: #2C313A; }
                .Critical { color: #FF5555; font-weight: bold; }
                .Important { color: #FFB86C; }
                .Moderate { color: #F1FA8C; }
                .Superseded { color: #6272A4; font-style: italic; opacity: 0.7; }
                a { color: #00CED1; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
            <script>
            function sortTable(n) {
              var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
              table = document.getElementById("vulnTable");
              switching = true;
              dir = "asc"; 
              while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                  shouldSwitch = false;
                  x = rows[i].getElementsByTagName("TD")[n];
                  y = rows[i + 1].getElementsByTagName("TD")[n];
                  if (dir == "asc") {
                    if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                      shouldSwitch = true;
                      break;
                    }
                  } else if (dir == "desc") {
                    if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                      shouldSwitch = true;
                      break;
                    }
                  }
                }
                if (shouldSwitch) {
                  rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                  switching = true;
                  switchcount ++;      
                } else {
                  if (switchcount == 0 && dir == "asc") {
                    dir = "desc";
                    switching = true;
                  }
                }
              }
            }
            </script>
        </head>
        <body>
            <h1>Offline Security Assessment Report</h1>
            <div class="summary">
                <h3>Executive Summary</h3>
                <p>Total Vulnerabilities Detected: <strong>{{TOTAL}}</strong></p>
                <p>Critical: {{CRIT}} | Important: {{IMP}}</p>
            </div>
            <p><i>Click table headers to sort.</i></p>
            <table id="vulnTable">
                <tr>
                    <th onclick="sortTable(0)">Severity &#x2195;</th>
                    <th onclick="sortTable(1)">CVE &#x2195;</th>
                    <th onclick="sortTable(2)">KB ID &#x2195;</th>
                    <th onclick="sortTable(3)">Status &#x2195;</th>
                    <th onclick="sortTable(4)">Title &#x2195;</th>
                    <th>Link</th>
                </tr>
                {{ROWS}}
            </table>
        </body>
        </html>
        """

    def generate_html_report(self):
        if not self.full_dataset:
            messagebox.showinfo("Report", "No data to report. Run a scan first.")
            return
            
        self.log_msg("Generating HTML report...")
        
        rows = ""
        c_crit = 0
        c_imp = 0
        
        for v in self.full_dataset:
            s_class = v.get('Severity', '')
            if s_class == 'Critical': c_crit += 1
            if s_class == 'Important': c_imp += 1
            
            status = v.get('Status', 'Active')
            row_class = "Superseded" if status == 'Superseded?' else s_class
            
            cve = v.get('CVE', '')
            link = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "#"
            
            rows += f"""
            <tr class="{row_class}">
                <td>{v.get('Severity')}</td>
                <td>{cve}</td>
                <td>{v.get('BulletinKB')}</td>
                <td>{status}</td>
                <td>{v.get('Title')}</td>
                <td><a href="{link}" target="_blank">View</a></td>
            </tr>
            """
            
        html = self.html_template().replace("{{ROWS}}", rows)
        html = html.replace("{{TOTAL}}", str(len(self.full_dataset)))
        html = html.replace("{{CRIT}}", str(c_crit)).replace("{{IMP}}", str(c_imp))
        
        fname = "offline_audit_report.html"
        try:
            with open(fname, "w", encoding="utf-8") as f:
                f.write(html)
            webbrowser.open(os.path.abspath(fname))
            self.log_msg(f"Report generated: {fname}")
        except Exception as e:
            self.log_msg(f"Report generation failed: {e}")

    def reset_all(self):
        self.grid.delete(*self.grid.get_children())
        self.full_dataset = []
        self.txt_path.delete(0, tk.END)
        self.search_var.set("")
        self.log_area.configure(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.configure(state='disabled')
        self.s_mode.set("local")
        self.switch_input()
        self.btn_go.state(['!disabled'])
        self.log_msg("Engine Reset.")

    def show_pops(self, ev):
        i = self.grid.identify_row(ev.y)
        if i:
            self.grid.selection_set(i)
            self.pops.post(ev.x_root, ev.y_root)

    def copy_lines(self):
        s = self.grid.selection()
        if not s: return
        v = self.grid.item(s[0])['values']
        self.master.clipboard_clear()
        self.master.clipboard_append(f"{v[0]} | {v[1]} | {v[2]} | {v[4]}")

    def copy_markdown(self):
        s = self.grid.selection()
        if not s: return
        v = self.grid.item(s[0])['values']
        md = f"| {v[0]} | {v[1]} | {v[2]} | {v[3]} | {v[4]} |"
        self.master.clipboard_clear()
        self.master.clipboard_append(md)

    def copy_url(self):
        s = self.grid.selection()
        if not s: return
        self.master.clipboard_clear()
        self.master.clipboard_append(self.grid.item(s[0])['values'][1])

    def launch_url(self):
        s = self.grid.selection()
        if not s: return
        cve = self.grid.item(s[0])['values'][1]
        if cve: webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{cve}")

    def switch_input(self):
        if self.s_mode.get() == "local":
            self.file_frame.pack_forget()
        else:
            self.file_frame.pack(side=tk.LEFT, padx=10)

    def find_file(self):
        p = filedialog.askopenfilename()
        if p:
             self.txt_path.delete(0, tk.END)
             self.txt_path.insert(0, p)
             self.log_msg(f"Target set to: {p}")

    def log_msg(self, msg):
        self.log_area.configure(state='normal')
        self.log_area.insert(tk.END, f">> {msg}\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state='disabled')
        self.master.update_idletasks()

    def execute_scan(self):
        self.grid.delete(*self.grid.get_children())
        self.full_dataset = []
        self.btn_go.state(['disabled'])
        
        t_file = None
        if self.s_mode.get() == "file":
             t_file = self.txt_path.get()
             if not t_file:
                 messagebox.showerror("Error", "No file selected!")
                 self.btn_go.state(['!disabled'])
                 return
        
        self.log_msg("Initializing scan...")
        threading.Thread(target=self.scan_thread, args=(t_file,), daemon=True).start()

    def scan_thread(self, fpath):
        raw_data = None
        raw_services = ""
        
        if fpath:
            # File Mode: Checks default encodings
            for enc in ['utf-8', 'utf-16', 'cp1252', 'mbcs', 'latin-1']:
                try:
                    with open(fpath, 'r', encoding=enc) as f:
                        buf = f.read()
                        if "Host Name" in buf or "OS Name" in buf or "System Type" in buf:
                            raw_data = buf
                            self.log_msg(f"File read success ({enc}).")
                            break
                except Exception:
                    continue
            
            if not raw_data:
                self.log_msg("FATAL: Could not read file.")
                self.master.after(0, lambda: self.btn_go.state(['!disabled']))
                return
        else:
            # Local Mode: We get the full suite
            info_pack = self.core.get_local_info()
            if info_pack:
                raw_data = info_pack
                raw_services = info_pack.get('services', '')
            
        if not raw_data:
            self.log_msg("Scan failed: No data recovered.")
            self.master.after(0, lambda: self.btn_go.state(['!disabled']))
            return

        sys_data = self.core.parse_sys_output(raw_data)
        

        if hasattr(self, 'core_db') and self.core_db:
             db = self.core_db
        else:
            # Retry loading? or Fail
            self.log_msg("[-] Vulnerability database not loaded. Retrying...")
            db = self.core.load_defs()
            if not db:
                 self.log_msg("[-] Critical: Failed to load definition database.")
                 self.master.after(0, lambda: self.btn_go.state(['!disabled']))
                 return
            self.core_db = db

        if not sys_data or not db:
            self.log_msg("Scan stopped due to errors.")
            self.master.after(0, lambda: self.btn_go.state(['!disabled']))
            return
            
        res = self.core.analyze(sys_data, db, services_blob=raw_services)
        lvl = {'Critical':0, 'Important':1, 'Moderate':2, 'Low':3}
        res.sort(key=lambda x: lvl.get(x.get('Severity'), 9))
        
        self.full_dataset = res
        self.master.after(0, self.render_res)

    def filter_results(self, *args):
        # Refresh the view based on filters
        self.render_res()

    def render_res(self):
        query = self.search_var.get().lower()
        show_super = self.show_superseded.get()
        
        self.grid.delete(*self.grid.get_children())
        
        cnt = 0
        for v in self.full_dataset:
             # Supersedence Filter
             status = v.get('Status', 'Active')
             if status == 'Superseded?' and not show_super:
                 continue
                 
             # Search Filter
             if query and query not in str(v).lower():
                 continue
                 
             s = v.get('Severity')
             self.grid.insert("", "end", values=(s, v.get('CVE'), v.get('BulletinKB'), status, v.get('Title')), tags=(status if status == 'Superseded?' else s,))
             cnt += 1
        
        self.log_msg(f"Displaying {cnt} results (Total Found: {len(self.full_dataset)})")
        self.btn_go.state(['!disabled'])

    def sort_table(self, col, rev):
        l = [(self.grid.set(k, col), k) for k in self.grid.get_children('')]
        l.sort(reverse=rev)
        for i, (val, k) in enumerate(l):
            self.grid.move(k, '', i)
        self.grid.heading(col, command=lambda: self.sort_table(col, not rev))

    def save_results(self):
        if not self.full_dataset:
            messagebox.showinfo("Export", "No data.")
            return
            
        fs = filedialog.asksaveasfilename(
            defaultextension=".csv", 
            filetypes=[("CSV Files","*.csv"), ("JSON Data", "*.json")]
        )
        if not fs: return
        
        try:
            if fs.lower().endswith(".json"):
                with open(fs, 'w', encoding='utf-8') as jf:
                    json.dump(self.full_dataset, jf, indent=4)
                self.log_msg(f"Exported JSON to {fs}")
            else:
                with open(fs, 'w', newline='', encoding='utf-8') as cf:
                    flds = ['Severity', 'CVE', 'BulletinKB', 'Title', 'AffectedProduct', 'Status']
                    w = csv.DictWriter(cf, fieldnames=flds)
                    w.writeheader()
                    for v in self.full_dataset:
                        r = {k: v.get(k, '') for k in flds}
                        w.writerow(r)
                self.log_msg(f"Exported CSV to {fs}")
            
            messagebox.showinfo("Export", f"Saved to {fs}")
        except Exception as e:
            self.log_msg(f"Export Error: {e}")
            messagebox.showerror("Error", f"Save failed: {e}")

def main():
    if len(sys.argv) > 1:
        p = argparse.ArgumentParser()
        p.add_argument("--local", action="store_true")
        p.add_argument("--systeminfo")
        a = p.parse_args()
        
        eng = CoreScanner()
        db = eng.load_defs()
        
        if a.local:
             info = eng.get_local_info()
             if info:
                 inf = eng.parse_sys_output(info)
                 if inf and db:
                     ret = eng.analyze(inf, db)
                     print(f"Found {len(ret)} vulnerabilities.")
                     for r in ret: print(f"{r.get('CVE')}|{r.get('Severity')}|{r.get('Title')}")
    else:
        root = tk.Tk()
        AppWindow(root)
        root.mainloop()

if __name__ == "__main__":
    main()
