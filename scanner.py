"""
Flask Vulnerability Scanner — Terminal UI Edition

Legal: Use only on systems you own or have written permission to test.

Requirements (in your venv):
    pip install flask requests python-dateutil python-nmap

System tools (optional, recommended):
    nmap, nikto

Run:
    python scanner.py
Open:
    http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string, jsonify
import socket
import ssl
import time
import subprocess
import shutil
from datetime import datetime
from dateutil import parser as dateparser

# ---- Configuration ----
SCANNER_NAME = "VulnScan"
NMAP_TIMEOUT = 120
NIKTO_TIMEOUT = 180

# Try python-nmap
try:
    import nmap as libnmap
    HAVE_PYTHON_NMAP = True
except Exception:
    HAVE_PYTHON_NMAP = False

# Check CLI availability
NMAP_CLI = shutil.which("nmap")
NIKTO_CLI = shutil.which("nikto")

app = Flask(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 123, 137, 139, 143, 161, 389, 443,
    445, 465, 587, 636, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080
]

# -------------------------
# Helpers
# -------------------------
def sanitize_target(target):
    t = (target or "").strip()
    if t == "":
        raise ValueError("Empty target.")
    return t

def resolve_host(target):
    info = {}
    try:
        ip = socket.gethostbyname(target)
        info['resolved_ip'] = ip
    except Exception as e:
        info['resolved_ip'] = None
        info['resolve_error'] = str(e)
    try:
        if info.get('resolved_ip'):
            rn = socket.gethostbyaddr(info['resolved_ip'])
            info['reverse_dns'] = rn[0]
    except Exception:
        pass
    return info

def tcp_connect_scan(ip, ports, timeout=1.0):
    results = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            start = time.time()
            s.connect((ip, p))
            elapsed = time.time() - start
            results[p] = {'open': True, 'rtt_s': round(elapsed, 3)}
        except Exception:
            results[p] = {'open': False}
        finally:
            try:
                s.close()
            except:
                pass
    return results

def banner_grab(ip, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = b""
        if port in (80, 8080, 8000):
            try:
                host_bytes = ip.encode() if isinstance(ip, str) else b""
                s.sendall(b"GET / HTTP/1.0\r\nHost: " + host_bytes + b"\r\n\r\n")
            except:
                pass
        elif port == 443:
            try:
                context = ssl.create_default_context()
                ss = context.wrap_socket(s, server_hostname=ip)
                host_bytes = ip.encode() if isinstance(ip, str) else b""
                ss.sendall(b"GET / HTTP/1.0\r\nHost: " + host_bytes + b"\r\n\r\n")
                banner = ss.recv(2048)
                ss.close()
                return banner.decode(errors='ignore').strip()
            except Exception:
                return "[ssl handshake/banner failed]"
        else:
            try:
                s.sendall(b"\r\n")
            except:
                pass
        try:
            banner = s.recv(2048)
        except:
            banner = b""
        s.close()
        return banner.decode(errors='ignore').strip()
    except Exception as e:
        return f"[banner error: {e}]"

def get_tls_info(ip, port=443, timeout=3.0):
    info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                info['cert'] = cert
                not_after = cert.get('notAfter')
                if not_after:
                    try:
                        dt = dateparser.parse(not_after)
                        info['cert_not_after'] = dt.isoformat()
                        info['cert_days_remaining'] = (dt - datetime.utcnow()).days
                    except Exception:
                        info['cert_not_after'] = not_after
                info['subject'] = cert.get('subject')
                info['issuer'] = cert.get('issuer')
    except Exception as e:
        info['tls_error'] = str(e)
    return info

def fetch_http_headers(ip, port=80, https=False, timeout=4.0):
    try:
        import requests
        if https:
            url = f"https://{ip}:{port}/" if port != 443 else f"https://{ip}/"
            r = requests.get(url, timeout=timeout, verify=False)
        else:
            url = f"http://{ip}:{port}/" if port != 80 else f"http://{ip}/"
            r = requests.get(url, timeout=timeout)
        return {'status_code': r.status_code, 'headers': dict(r.headers)}
    except Exception as e:
        return {'error': str(e)}

# -------------------------
# Nmap integration
# -------------------------
def run_nmap_scan(ip, ports, timeout=60):
    port_str = ",".join(str(p) for p in ports)
    result = {'available': False, 'method': None, 'raw': None, 'error': None}
    try:
        if HAVE_PYTHON_NMAP:
            result['available'] = True
            result['method'] = 'python-nmap'
            nm = libnmap.PortScanner()
            nm.scan(hosts=ip, ports=port_str, arguments='-sV --version-intensity 0')
            result['raw'] = nm[ip] if ip in nm.all_hosts() else {}
            return result
        elif NMAP_CLI:
            result['available'] = True
            result['method'] = 'nmap-cli'
            cmd = ["nmap", "-sV", "--version-intensity", "0", "-p", port_str, ip]
            completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            result['raw'] = {'stdout': completed.stdout, 'stderr': completed.stderr, 'returncode': completed.returncode}
            return result
        else:
            result['available'] = False
            result['error'] = "nmap (python library or CLI) not found"
            return result
    except subprocess.TimeoutExpired:
        result['error'] = f"nmap timed out after {timeout}s"
        return result
    except Exception as e:
        result['error'] = str(e)
        return result

# -------------------------
# Nikto integration
# -------------------------
def run_nikto_scan(target_host, port, https=False, timeout=90, max_output_chars=12000):
    if not NIKTO_CLI:
        return {'available': False, 'error': 'nikto CLI not found'}
    cmd = [NIKTO_CLI, "-h", target_host, "-p", str(port), "-Display", "V"]
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = completed.stdout + ("\n\nSTDERR:\n" + completed.stderr if completed.stderr else "")
        if len(out) > max_output_chars:
            out_trunc = out[:max_output_chars] + "\n\n[output truncated]"
        else:
            out_trunc = out
        return {'available': True, 'stdout_truncated': out_trunc, 'returncode': completed.returncode}
    except subprocess.TimeoutExpired:
        return {'available': True, 'error': f"nikto timed out after {timeout}s"}
    except Exception as e:
        return {'available': True, 'error': str(e)}

# -------------------------
# Analysis
# -------------------------
def analyze_findings(report):
    recs = []
    open_ports = [p for p, v in report['ports'].items() if v.get('open')]
    if 22 in open_ports:
        recs.append("Port 22 (SSH) open — use key-based auth and keep OpenSSH updated.")
    if 23 in open_ports:
        recs.append("Port 23 (Telnet) open — Telnet is insecure; disable and use SSH.")
    if 80 in open_ports or 8080 in open_ports:
        recs.append("HTTP port open — consider HSTS and redirecting to HTTPS where appropriate.")
    if 443 in open_ports:
        tls = report.get('tls') or {}
        days = tls.get('cert_days_remaining')
        if days is not None and days < 30:
            recs.append(f"TLS certificate expires in {days} days — renew soon.")
    if not recs:
        recs.append("No immediate high-level recommendations detected; manual review recommended.")
    return recs

# -------------------------
# UI Template
# -------------------------
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ scanner_name }} - Network Vulnerability Scanner</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background: #0a0e14;
      font-family: 'Courier New', Courier, monospace;
      color: #00ff00;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      overflow-x: hidden;
    }

    .terminal-container {
      width: 100%;
      max-width: 900px;
      background: #000000;
      border: 2px solid #333;
      border-radius: 8px;
      box-shadow: 0 0 40px rgba(0, 255, 0, 0.15);
      overflow: hidden;
    }

    .terminal-header {
      background: #1a1a1a;
      padding: 10px 15px;
      display: flex;
      align-items: center;
      gap: 8px;
      border-bottom: 1px solid #333;
    }

    .terminal-button {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      display: inline-block;
    }

    .btn-close { background: #ff5f56; }
    .btn-minimize { background: #ffbd2e; }
    .btn-maximize { background: #27c93f; }

    .terminal-title {
      margin-left: 12px;
      color: #888;
      font-size: 12px;
      letter-spacing: 0.5px;
    }

    .terminal-body {
      padding: 30px;
      min-height: 500px;
    }

    .ascii-art {
      color: #00ff00;
      font-size: 10px;
      line-height: 1.2;
      margin-bottom: 20px;
      text-align: center;
      white-space: pre;
      font-weight: bold;
    }

    .terminal-output {
      margin-bottom: 20px;
    }

    .output-line {
      margin: 8px 0;
      line-height: 1.6;
    }

    .prompt-user {
      color: #00ffff;
    }

    .prompt-host {
      color: #ffff00;
    }

    .text-cyan { color: #00ffff; }
    .text-gray { color: #888; }
    .text-white { color: #ffffff; }

    .input-section {
      margin-top: 30px;
    }

    .command-line {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 15px;
    }

    .command-prompt {
      color: #00ff00;
      font-weight: bold;
      white-space: nowrap;
    }

    input[type="text"] {
      flex: 1;
      background: transparent;
      border: none;
      color: #ffffff;
      font-family: 'Courier New', Courier, monospace;
      font-size: 16px;
      outline: none;
      padding: 5px;
      caret-color: #00ff00;
    }

    input[type="text"]::placeholder {
      color: #555;
    }

    .options-line {
      display: flex;
      gap: 30px;
      margin: 15px 0;
      padding-left: 30px;
    }

    .checkbox-wrapper {
      display: flex;
      align-items: center;
      gap: 10px;
      cursor: pointer;
    }

    input[type="checkbox"] {
      width: 16px;
      height: 16px;
      cursor: pointer;
      accent-color: #00ff00;
    }

    .checkbox-label {
      color: #00ffff;
      cursor: pointer;
      user-select: none;
    }

    .button-line {
      margin-top: 20px;
      padding-left: 30px;
    }

    button {
      background: transparent;
      border: 2px solid #00ff00;
      color: #00ff00;
      padding: 10px 30px;
      font-family: 'Courier New', Courier, monospace;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s;
      letter-spacing: 1px;
      font-weight: bold;
    }

    button:hover {
      background: #00ff00;
      color: #000;
      box-shadow: 0 0 20px rgba(0, 255, 0, 0.5);
    }

    button:active {
      transform: translateY(2px);
    }

    .warning-box {
      border: 1px solid #ff4444;
      background: rgba(255, 68, 68, 0.1);
      padding: 15px;
      margin-top: 20px;
      border-radius: 4px;
    }

    .warning-title {
      color: #ff4444;
      font-weight: bold;
      margin-bottom: 8px;
    }

    .warning-text {
      color: #ffaa44;
      font-size: 13px;
      line-height: 1.5;
    }

    .info-box {
      border: 1px solid #00ffff;
      background: rgba(0, 255, 255, 0.05);
      padding: 12px;
      margin-top: 15px;
      border-radius: 4px;
    }

    .info-text {
      color: #00ffff;
      font-size: 13px;
    }

    @media (max-width: 600px) {
      .terminal-body {
        padding: 20px;
      }

      .ascii-art {
        font-size: 6px;
      }

      .options-line {
        flex-direction: column;
        gap: 10px;
      }
    }
  </style>
</head>
<body>
  <div class="terminal-container">
    <div class="terminal-header">
      <span class="terminal-button btn-close"></span>
      <span class="terminal-button btn-minimize"></span>
      <span class="terminal-button btn-maximize"></span>
      <span class="terminal-title">{{ scanner_name }} Terminal v1.0.0</span>
    </div>
    
    <div class="terminal-body">
      <div class="ascii-art">
╦  ╦┬ ┬┬  ┌┐┌╔═╗┌─┐┌─┐┌┐┌
╚╗╔╝│ ││  │││╚═╗│  ├─┤│││
 ╚╝ └─┘┴─┘┘└┘╚═╝└─┘┴ ┴┘└┘
Network Vulnerability Scanner</div>

      <div class="terminal-output">
        <div class="output-line">
          <span class="text-cyan">┌──[</span><span class="prompt-user">root</span><span class="text-gray">@</span><span class="prompt-host">scanner</span><span class="text-cyan">]</span>
        </div>
        <div class="output-line">
          <span class="text-cyan">└─$</span> <span class="text-white">Initializing {{ scanner_name }} security toolkit...</span>
        </div>
        <div class="output-line text-gray">
          [✓] Port scanner module loaded
        </div>
        <div class="output-line text-gray">
          [✓] Banner grabbing enabled
        </div>
        <div class="output-line text-gray">
          [✓] TLS/SSL analyzer ready
        </div>
        <div class="output-line text-gray">
          {% if nmap_available %}[✓] Nmap integration detected{% else %}[✗] Nmap not available{% endif %}
        </div>
        <div class="output-line text-gray">
          {% if nikto_available %}[✓] Nikto vulnerability scanner available{% else %}[✗] Nikto not available{% endif %}
        </div>
        <div class="output-line" style="margin-top: 15px;">
          <span class="text-white">Ready to scan. Enter target host or IP address.</span>
        </div>
      </div>

      <form method="post" action="{{ url_for('scan') }}">
        <div class="input-section">
          <div class="command-line">
            <span class="command-prompt">root@scanner:~#</span>
            <input 
              type="text" 
              name="target"
              placeholder="example.com or 192.168.1.1" 
              autofocus
              required
            >
          </div>

          <div class="options-line">
            <label class="checkbox-wrapper">
              <input type="checkbox" name="run_nmap" id="nmapCheck">
              <span class="checkbox-label">[  ] Enable Nmap deep scan</span>
            </label>
            
            <label class="checkbox-wrapper">
              <input type="checkbox" name="run_nikto" id="niktoCheck">
              <span class="checkbox-label">[  ] Enable Nikto web scanner</span>
            </label>
          </div>

          <div class="button-line">
            <button type="submit">EXECUTE SCAN</button>
          </div>
        </div>

        <div class="info-box">
          <div class="info-text">
            → Scan performs: TCP port scan, banner grabbing, TLS certificate check, HTTP header analysis
          </div>
        </div>

        <div class="warning-box">
          <div class="warning-title">⚠ LEGAL NOTICE</div>
          <div class="warning-text">
            Only scan systems you own or have explicit written permission to test.<br>
            Unauthorized scanning may violate laws and regulations.
          </div>
        </div>
      </form>
    </div>
  </div>

  <script>
    document.getElementById('nmapCheck').addEventListener('change', function(e) {
      const label = e.target.nextElementSibling;
      label.textContent = e.target.checked ? '[✓] Enable Nmap deep scan' : '[  ] Enable Nmap deep scan';
    });

    document.getElementById('niktoCheck').addEventListener('change', function(e) {
      const label = e.target.nextElementSibling;
      label.textContent = e.target.checked ? '[✓] Enable Nikto web scanner' : '[  ] Enable Nikto web scanner';
    });
  </script>
</body>
</html>
"""

REPORT_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{ scanner_name }} — Report: {{ target }}</title>
  <style>
    body { 
      font-family: 'Courier New', Courier, monospace; 
      background:#0a0e14; 
      color:#e6eef8; 
      padding:26px; 
    }
    .brand { text-align:center; margin-bottom:18px; }
    .brand h1 { 
      margin:0; 
      font-size:28px; 
      background: linear-gradient(90deg,#00ff00,#00ffff); 
      -webkit-background-clip:text; 
      background-clip:text; 
      color:transparent; 
    }
    .brand .muted { color:#9fb1c7; font-size:12px; margin-top:6px; }
    .card { 
      background:#000; 
      border:1px solid #333; 
      border-radius:12px; 
      box-shadow:0 0 20px rgba(0,255,0,0.1); 
      padding:18px; 
      margin-bottom:14px; 
    }
    h2 { margin:0 0 10px 0; font-size:18px; color:#00ffff; }
    h3 { margin:4px 0 8px; color:#00ff00; }
    pre { 
      background:#0b1120;
      color:#00ff00;
      padding:12px;
      border-radius:8px;
      overflow:auto;
      border: 1px solid #1a1a1a;
    }
    table { width:100%; border-collapse:collapse; }
    td, th { padding:8px; border-bottom:1px solid #1a1a1a; text-align:left; vertical-align:top; }
    .open { color:#00ff00; font-weight:600; }
    .closed { color:#555; }
    .muted { color:#888; font-size:13px; }
    .json { 
      font-family: 'Courier New', monospace; 
      font-size:12px; 
      background:#0b1221; 
      color:#00ff00; 
      padding:10px; 
      border-radius:8px; 
      overflow:auto; 
    }
    .btn-back { 
      display:inline-block; 
      margin-bottom:12px; 
      padding:10px 20px; 
      background:transparent;
      border: 2px solid #00ffff;
      color:#00ffff; 
      border-radius:8px; 
      text-decoration:none;
      font-family: 'Courier New', Courier, monospace;
      transition: all 0.3s;
    }
    .btn-back:hover {
      background: #00ffff;
      color: #000;
    }
  </style>
</head>
<body>
  <div class="brand">
    <h1>{{ scanner_name }}</h1>
    <div class="muted">Report for <strong>{{ target }}</strong> &middot; scanned at {{ scanned_at }}</div>
  </div>

  <a class="btn-back" href="{{ url_for('index') }}">&larr; NEW SCAN</a>

  <div class="card">
    <h2>SCAN SUMMARY</h2>
    <p><strong>Target:</strong> {{ target }}</p>
    <p><strong>Resolved IP:</strong> {{ report.resolved_ip or 'N/A' }} 
      {% if report.reverse_dns %}(<em>{{ report.reverse_dns }}</em>){% endif %}
    </p>
    <p><strong>Open ports:</strong>
      {% if open_ports|length %}
        {% for p in open_ports %}
          <span class="open">{{ p }}</span>{% if not loop.last %}, {% endif %}
        {% endfor %}
      {% else %}
        <span class="closed">none of the common ports were open</span>
      {% endif %}
    </p>
  </div>

  <div class="card">
    <h2>PORTS & BANNERS</h2>
    <table>
      <thead>
        <tr>
          <th style="width:80px">Port</th>
          <th style="width:80px">Status</th>
          <th style="width:100px">RTT (s)</th>
          <th>Banner / Notes</th>
        </tr>
      </thead>
      <tbody>
      {% for port, v in report.ports|dictsort %}
        <tr>
          <td>{{ port }}</td>
          <td>
            {% if v.open %}
              <span class="open">OPEN</span>
            {% else %}
              <span class="closed">CLOSED</span>
            {% endif %}
          </td>
          <td>{{ v.rtt_s or '-' }}</td>
          <td><pre style="white-space:pre-wrap; margin:0;">{{ v.banner or '' }}</pre></td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>TLS / HTTPS</h2>
    {% if report.tls %}
      {% if report.tls.cert %}
        <p><strong>Certificate expires:</strong> {{ report.tls.cert_not_after }} (in {{ report.tls.cert_days_remaining }} days)</p>
        <p><strong>Issuer:</strong> {{ report.tls.issuer }}</p>
      {% else %}
        <p class="muted">No certificate info: {{ report.tls.tls_error }}</p>
      {% endif %}
    {% else %}
      <p class="muted">HTTPS not checked.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>HTTP HEADERS</h2>
    {% if report.http %}
      {% if report.http.error %}
        <p class="muted">HTTP fetch error: {{ report.http.error }}</p>
      {% else %}
        <p><strong>Status:</strong> {{ report.http.status_code }}</p>
        <pre class="json">{{ report.http.headers | tojson(indent=2) }}</pre>
      {% endif %}
    {% else %}
      <p class="muted">HTTP not checked.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>NMAP SCAN</h2>
    {% if report.nmap %}
      {% if report.nmap.available %}
        <p class="muted">Method: {{ report.nmap.method }}</p>
        <pre class="json">{{ report.nmap.raw | tojson(indent=2) }}</pre>
      {% else %}
        <p class="muted">Nmap not available: {{ report.nmap.error }}</p>
      {% endif %}
    {% else %}
      <p class="muted">Nmap scan not requested.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>NIKTO SCAN</h2>
    {% if report.nikto %}
      {% if report.nikto.cli_present %}
        {% for r in report.nikto.reports %}
          <h3>Port {{ r.port }} {% if r.https %}(HTTPS){% endif %}</h3>
          {% if r.result.available %}
            {% if r.result.stdout_truncated %}
              <pre class="json">{{ r.result.stdout_truncated }}</pre>
            {% elif r.result.error %}
              <p class="muted">Nikto error: {{ r.result.error }}</p>
            {% else %}
              <p class="muted">No output captured.</p>
            {% endif %}
          {% else %}
            <p class="muted">Nikto not available: {{ r.result.error }}</p>
          {% endif %}
        {% endfor %}
      {% else %}
        <p class="muted">Nikto CLI not found on this system.</p>
      {% endif %}
    {% else %}
      <p class="muted">Nikto scan not requested.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>RECOMMENDATIONS</h2>
    <ul>
      {% for r in report.recommendations %}
        <li>{{ r }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>RAW JSON DATA</h2>
    <pre class="json">{{ report | tojson(indent=2) }}</pre>
  </div>

</body>
</html>
"""

# -------------------------
# Flask routes
# -------------------------
@app.route('/')
def index():
    return render_template_string(
        INDEX_HTML, 
        scanner_name=SCANNER_NAME,
        nmap_available=(HAVE_PYTHON_NMAP or NMAP_CLI),
        nikto_available=bool(NIKTO_CLI)
    )

@app.route('/scan', methods=['POST'])
def scan():
    target = sanitize_target(request.form.get('target',''))
    scanned_at = datetime.utcnow().isoformat() + 'Z'
    run_nmap_flag  = request.form.get('run_nmap') == 'on'
    run_nikto_flag = request.form.get('run_nikto') == 'on'
    
    report = {
        'target': target,
        'scanned_at': scanned_at,
        'resolved_ip': None,
        'reverse_dns': None,
        'ports': {},
        'tls': None,
        'http': None,
        'nmap': None,
        'nikto': None,
        'recommendations': []
    }

    try:
        resolve_info = resolve_host(target)
        report['resolved_ip'] = resolve_info.get('resolved_ip')
        report['reverse_dns'] = resolve_info.get('reverse_dns')
        ip = report['resolved_ip'] or target
    except Exception as e:
        report['resolve_error'] = str(e)
        ip = target

    # Port scan
    try:
        port_results = tcp_connect_scan(ip, COMMON_PORTS, timeout=1.2)
        for p, info in port_results.items():
            banner = ""
            rtt = info.get('rtt_s')
            if info.get('open'):
                banner = banner_grab(ip, p)
            report['ports'][p] = {'open': info.get('open', False), 'rtt_s': rtt, 'banner': banner}
    except Exception as e:
        report['port_scan_error'] = str(e)

    # TLS check
    try:
        if report['ports'].get(443,{}).get('open'):
            report['tls'] = get_tls_info(ip, 443)
        else:
            tls_info = get_tls_info(ip, 443)
            if tls_info and 'cert' in tls_info:
                report['tls'] = tls_info
    except Exception as e:
        report['tls_error'] = str(e)

    # HTTP headers
    try:
        if report['ports'].get(80,{}).get('open'):
            report['http'] = fetch_http_headers(ip, 80, https=False)
        elif report['ports'].get(443,{}).get('open'):
            report['http'] = fetch_http_headers(ip, 443, https=True)
    except Exception as e:
        report['http_error'] = str(e)

    # Nmap (optional)
    try:
        if run_nmap_flag:
            report['nmap'] = run_nmap_scan(ip, COMMON_PORTS, timeout=NMAP_TIMEOUT)
        else:
            report['nmap'] = None
    except Exception as e:
        report['nmap_error'] = str(e)

    # Nikto (optional)
    try:
        if run_nikto_flag:
            nikto_runs = []
            if report['ports'].get(443,{}).get('open'):
                nikto_runs.append({'port': 443, 'https': True})
            if report['ports'].get(80,{}).get('open'):
                nikto_runs.append({'port': 80, 'https': False})
            if report['ports'].get(8080,{}).get('open'):
                nikto_runs.append({'port': 8080, 'https': False})
            nikto_reports = []
            for r in nikto_runs:
                target_host = target
                nr = run_nikto_scan(target_host, r['port'], https=r['https'], timeout=NIKTO_TIMEOUT)
                nikto_reports.append({'port': r['port'], 'https': r['https'], 'result': nr})
            report['nikto'] = {'available': bool(nikto_reports), 'reports': nikto_reports, 'cli_present': bool(NIKTO_CLI)}
        else:
            report['nikto'] = None
    except Exception as e:
        report['nikto_error'] = str(e)

    # Recommendations
    try:
        report['recommendations'] = analyze_findings(report)
    except Exception:
        report['recommendations'] = ["Analysis error."]

    # Compute open ports for the template
    open_ports = sorted([p for p, v in report['ports'].items() if v.get('open')])

    return render_template_string(
        REPORT_HTML,
        target=target,
        report=report,
        scanned_at=scanned_at,
        scanner_name=SCANNER_NAME,
        open_ports=open_ports
    )

if __name__ == '__main__':
    print(f"Starting {SCANNER_NAME} on http://127.0.0.1:5000")
    print("Press CTRL+C to quit")
    app.run(host='127.0.0.1', port=5000, debug=True)
