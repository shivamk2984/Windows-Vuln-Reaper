# Windows-Vuln-Reaper
![Windows-Vuln-Reaper Logo][(https://github.com/shivamk2984/Windows-Vuln-Reaper/blob/main/assets/final_logo.png)](https://github.com/shivamk2984/assets/blob/main/final_logo.png?raw=true)

**by codeinecasket**

<h3 align="left">Languages and Tools:</h3>
<p align="left"> <a href="https://www.python.org" target="_blank" rel="noreferrer"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="python" width="40" height="40"/> </a> </p>


A professional-grade, standalone Windows vulnerability auditing tool. It analyzes a Windows system's patch levels against a comprehensive database of vulnerabilities to detect missing security updates and configuration weaknesses.

**Fully self-contained in a single executable.**

##  Key Features

*   **Dark Audit Interface:** A "dark mode" professional UI with high-contrast data visualization.

*   **Deep Context Awareness:**
    *   **Supersedence Logic:** Automatically hides thousands of "superseded" vulnerabilities if a newer patch is present (High Water Mark logic).
    *   **Service & Config Analysis:** Checks if vulnerable services (e.g., Print Spooler, IIS) are actually *running* before flagging them.
    *   **Build-Precise:** Accurately maps Build Numbers (e.g., 22621 -> 22H2) to prevent false positives.
*   **Interactive Reporting:**
    *   Generates a **Sortable HTML Report** (`security_audit_report.html`) with direct links to NIST CVE data.
    *   Exports data to **JSON** or **CSV** for external processing.
    *   Copy rows as **Markdown** directly from the UI for easy report writing.
*   **Future-Proof:** Supports dropping a `versions.json` file in the same directory to add support for future Windows releases without recompiling.
*   **Hybrid Scan Modes:** 
    *   **Local Audit:** Auto-collects data from the running machine.
    *   **File Audit:** Analyzes offline `systeminfo` output files from other machines.

##  Quick Start

### 1. Download & Run
Double-click `Windows-Vuln-Reaper.exe`.  
*No installation or dependencies required.*

### 2. Scanning
*   **Scan Local**: Select "LOCAL AUDIT" and click **START SCAN**.
*   **Scan Remote**: Select "FILE AUDIT", browse for a `systeminfo.txt` file, and scan.

### 3. Reporting
*   Click **REPORT** to generate and open the interactive HTML Dashboard.
*   Click **EXPORT DATA** to save findings as JSON or CSV.
*   Right-click any row to **Copy as Markdown** or **Open NIST Page**.

##  Advanced Usage

### Adding Support for New Windows Versions
If Microsoft releases a new version (e.g., Windows 12 or 24H2), you don't need to wait for an update. Just create a `versions.json` file in the tool's folder:
```json
{
    "26100": "24H2",
    "29000": "30H2"
}
```

### Command Line Mode
Useful for automation:
```cmd
REM Update the database (Ephemeral download)
Windows-Vuln-Reaper.exe --update

REM Scan local machine silently (console output)
Windows-Vuln-Reaper.exe --local
```

##  Credits
**Developed by codeinecasket**  
Based on research from the WES-NG project.

##  How to Build (from source)
If you prefer to run from source or build your own executable:

1.  **Install Python 3.x**
2.  **Install Dependencies:**
    ```bash
    pip install tkinter
    ```
    *(Note: tkinter is usually included with Python, but ensure it's selected during install)*
3.  **Run Directly:**
    ```bash
    python windows_vuln_reaper.py
    ```
4.  **Build Executable:**
    ```bash
    pip install pyinstaller
    pyinstaller --onefile --noconsole --name "Windows-Vuln-Reaper" windows_vuln_reaper.py
    ```

##  License
This tool is for **educational and authorized security auditing purposes only**. Use responsibly.
