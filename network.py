import socket
from datetime import datetime
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI()

AUDIT_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "detail": "Unencrypted file transfer. Credentials and data transmitted in plaintext.", "action": "Disable FTP or migrate to SFTP/FTPS."},
    22: {"service": "SSH", "risk": "LOW", "detail": "Secure administrative shell. Exposure on public interfaces invites brute-force.", "action": "Enforce key-based authentication and disable root login."},
    23: {"service": "TELNET", "risk": "CRITICAL", "detail": "Legacy remote management. All sessions transmitted without encryption.", "action": "Terminate service immediately. Replace with SSH."},
    53: {"service": "DNS", "risk": "LOW", "detail": "Domain resolution port. If exposed externally, can be abused in amplification attacks.", "action": "Ensure resolver is restricted to local queries only."},
    80: {"service": "HTTP", "risk": "MEDIUM", "detail": "Unencrypted web service. Administration panels exposed here are vulnerable to snooping.", "action": "Redirect all traffic to HTTPS (port 443) with HSTS enabled."},
    443: {"service": "HTTPS", "risk": "INFO", "detail": "Encrypted web service.", "action": "Verify TLS certificate validity and disable deprecated protocols (TLS 1.0/1.1)."},
    445: {"service": "SMB", "risk": "CRITICAL", "detail": "Direct-hosted SMB file sharing. Historically susceptible to remote exploitation.", "action": "Block port 445 at router boundary; restrict SMB access to local subnets only."},
    3389: {"service": "RDP", "risk": "HIGH", "detail": "Windows Remote Desktop. Frequent target for credential spraying and automated scans.", "action": "Place behind VPN gateway or enforce Network Level Authentication (NLA)."},
    8080: {"service": "HTTP-ALT", "risk": "MEDIUM", "detail": "Secondary web management console.", "action": "Confirm authentication controls and disable unused web endpoints."}
}

class ScanRequest(BaseModel):
    target_ip: str

def check_port(ip: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.35)
    try:
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except Exception:
        return False

@app.post("/api/scan")
def run_scan(payload: ScanRequest):
    target = payload.target_ip.strip()
    if not target:
        target = "127.0.0.1"

    open_findings = []
    total_ports = len(AUDIT_PORTS)
    critical_count = 0
    high_count = 0

    for port, meta in AUDIT_PORTS.items():
        is_open = check_port(target, port)
        if is_open:
            if meta["risk"] == "CRITICAL":
                critical_count += 1
            elif meta["risk"] == "HIGH":
                high_count += 1
            open_findings.append({
                "port": port,
                "service": meta["service"],
                "risk": meta["risk"],
                "detail": meta["detail"],
                "action": meta["action"]
            })

    if critical_count > 0:
        posture = "CRITICAL RISK"
    elif high_count > 0:
        posture = "ELEVATED RISK"
    elif len(open_findings) > 0:
        posture = "ACCEPTABLE / REVIEW"
    else:
        posture = "SECURE / HARDENED"

    return {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_scanned": total_ports,
        "open_count": len(open_findings),
        "posture": posture,
        "findings": open_findings
    }

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Network Vulnerability Scanner</title>
  <style>
    :root {
      --bg: #121214;
      --card: #18181b;
      --border: #27272a;
      --text: #f4f4f5;
      --muted: #a1a1aa;
      --bar-bg: #27272a;
      --accent: #ffffff;
      --status-crit: #ef4444;
      --status-warn: #f59e0b;
      --status-pass: #10b981;
      --status-info: #3b82f6;
    }
    body.light {
      --bg: #f4f4f5;
      --card: #ffffff;
      --border: #e4e4e7;
      --text: #09090b;
      --muted: #71717a;
      --bar-bg: #e4e4e7;
      --accent: #09090b;
      --status-crit: #dc2626;
      --status-warn: #d97706;
      --status-pass: #059669;
      --status-info: #2563eb;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: monospace;
      display: flex;
      justify-content: center;
      min-height: 100vh;
      padding: 1.5rem;
    }
    .wrapper {
      width: 100%;
      max-width: 900px;
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }
    .container {
      background: var(--card);
      border: 1px solid var(--border);
      padding: 1.5rem;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.75rem;
      margin-bottom: 1.25rem;
    }
    .title {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .btn {
      background: transparent;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 4px 8px;
      font-family: inherit;
      font-size: 0.75rem;
      cursor: pointer;
    }
    .btn:hover {
      border-color: var(--accent);
    }
    .btn-submit {
      background: var(--text);
      color: var(--bg);
      border: 1px solid var(--text);
      padding: 0.6rem 1rem;
      font-family: inherit;
      font-size: 0.75rem;
      font-weight: bold;
      cursor: pointer;
    }
    .scan-form {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1.25rem;
    }
    input[type="text"] {
      flex: 1;
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.6rem;
      font-family: inherit;
      font-size: 0.8rem;
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 0.5rem;
      border: 1px solid var(--border);
      padding: 0.75rem;
      font-size: 0.75rem;
      margin-bottom: 1.25rem;
    }
    .metric-item {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .metric-label {
      color: var(--muted);
      font-size: 0.7rem;
    }
    .metric-val {
      font-size: 0.95rem;
      font-weight: bold;
    }
    .status-crit { color: var(--status-crit); }
    .status-warn { color: var(--status-warn); }
    .status-pass { color: var(--status-pass); }
    .status-info { color: var(--status-info); }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.75rem;
      margin-top: 0.5rem;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 0.6rem;
      text-align: left;
    }
    th {
      color: var(--muted);
      font-weight: normal;
    }
    .report-card {
      margin-top: 1rem;
      border: 1px solid var(--border);
      background: var(--bg);
      padding: 1rem;
      display: none;
    }
    .report-title {
      font-size: 0.8rem;
      text-transform: uppercase;
      margin-bottom: 0.5rem;
      letter-spacing: 0.5px;
    }
    .report-list {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .report-item {
      padding: 0.5rem;
      border: 1px solid var(--border);
      background: var(--card);
    }
  </style>
</head>
<body class="dark">
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <span class="title">SEC://NET-VULN-AUDITOR</span>
        <button class="btn" id="themeBtn" onclick="toggleTheme()">(Light)</button>
      </div>

      <form class="scan-form" onsubmit="handleScan(event)">
        <input type="text" id="targetIp" value="127.0.0.1" placeholder="TARGET HOST OR IP..." required>
        <button type="submit" class="btn-submit" id="scanBtn">RUN AUDIT</button>
      </form>

      <div class="metrics">
        <div class="metric-item">
          <span class="metric-label">TARGET:</span>
          <span class="metric-val" id="metricTarget">NONE</span>
        </div>
        <div class="metric-item">
          <span class="metric-label">PORTS CHECKED:</span>
          <span class="metric-val" id="metricScanned">0</span>
        </div>
        <div class="metric-item">
          <span class="metric-label">OPEN SERVICES:</span>
          <span class="metric-val" id="metricOpen">0</span>
        </div>
        <div class="metric-item">
          <span class="metric-label">POSTURE:</span>
          <span class="metric-val" id="metricPosture">IDLE</span>
        </div>
      </div>

      <div class="header" style="margin-top: 1.5rem; margin-bottom: 0.5rem;">
        <span class="title">DETECTED EXPOSURES</span>
      </div>

      <table>
        <thead>
          <tr>
            <th>PORT</th>
            <th>SERVICE</th>
            <th>SEVERITY</th>
            <th>EXPOSURE PROFILE</th>
          </tr>
        </thead>
        <tbody id="findingsTableBody">
          <tr><td colspan="4">AWAITING SCAN EXECUTION</td></tr>
        </tbody>
      </table>

      <div class="report-card" id="reportCard">
        <div class="report-title">HARDENING & MITIGATION DIRECTIVES</div>
        <div class="report-list" id="reportDirectives"></div>
      </div>
    </div>
  </div>

  <script>
    function toggleTheme() {
      const body = document.body;
      const btn = document.getElementById("themeBtn");
      if (body.classList.contains("dark")) {
        body.classList.remove("dark");
        body.classList.add("light");
        btn.innerText = "(Dark)";
      } else {
        body.classList.remove("light");
        body.classList.add("dark");
        btn.innerText = "(Light)";
      }
    }

    async function handleScan(e) {
      e.preventDefault();
      const target = document.getElementById("targetIp").value;
      const btn = document.getElementById("scanBtn");
      const posture = document.getElementById("metricPosture");

      btn.disabled = true;
      btn.innerText = "SCANNING...";
      posture.innerText = "PROBING";
      posture.className = "metric-val";

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target_ip: target })
        });
        const data = await res.json();
        renderResults(data);
      } catch (err) {
        posture.innerText = "ERROR";
        posture.className = "metric-val status-crit";
      } finally {
        btn.disabled = false;
        btn.innerText = "RUN AUDIT";
      }
    }

    function renderResults(data) {
      document.getElementById("metricTarget").innerText = data.target;
      document.getElementById("metricScanned").innerText = data.total_scanned;
      document.getElementById("metricOpen").innerText = data.open_count;
      
      const posture = document.getElementById("metricPosture");
      posture.innerText = data.posture;
      if (data.posture.includes("CRITICAL")) posture.className = "metric-val status-crit";
      else if (data.posture.includes("ELEVATED")) posture.className = "metric-val status-warn";
      else if (data.posture.includes("SECURE")) posture.className = "metric-val status-pass";
      else posture.className = "metric-val status-info";

      const tbody = document.getElementById("findingsTableBody");
      const reportCard = document.getElementById("reportCard");
      const directives = document.getElementById("reportDirectives");

      tbody.innerHTML = "";
      directives.innerHTML = "";

      if (data.findings.length === 0) {
        tbody.innerHTML = "<tr><td colspan='4'>ZERO ACCESSIBLE PORTS DISCOVERED - HOST FILTERED OR OFFLINE</td></tr>";
        reportCard.style.display = "block";
        directives.innerHTML = "<div class='report-item'>No open listening ports detected in the standard audit surface. Maintain existing host firewall rules.</div>";
        return;
      }

      data.findings.forEach(f => {
        let sevClass = "status-info";
        if (f.risk === "CRITICAL") sevClass = "status-crit";
        else if (f.risk === "HIGH" || f.risk === "MEDIUM") sevClass = "status-warn";

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${f.port}</td>
          <td>${f.service}</td>
          <td class="${sevClass}">${f.risk}</td>
          <td>${f.detail}</td>
        `;
        tbody.appendChild(tr);

        const dItem = document.createElement("div");
        dItem.className = "report-item";
        dItem.innerHTML = `<strong>PORT ${f.port} (${f.service}):</strong> ${f.action}`;
        directives.appendChild(dItem);
      });

      reportCard.style.display = "block";
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML_PAGE

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)