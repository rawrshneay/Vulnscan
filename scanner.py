# scanner.py
"""
Flask Vulnerability Scanner — single-file with Nmap & Nikto integration.

Legal: Use only on systems you own or have written permission to test.

Requirements (in your venv):
    pip install flask requests python-dateutil python-nmap   # python-nmap optional
System tools (optional, recommended):
    nmap, nikto

Run:
    python scanner.py
Open:
    http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string
import socket, ssl, time, subprocess, shutil
from datetime import datetime
from dateutil import parser as dateparser

# ---- App name shown in UI ----
SCANNER_NAME = "VulnScan"   # change this to your preferred name

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
# UI Templates
# -------------------------
INDEX_HTML = f"""
<!doctype html>
<html>
<head>
  <title>{{{{ scanner_name }}}} — Vulnerability Scanner</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg:#070b12; --panel:#0f172a; --ink:#e2e8f0; --muted:#94a3b8; --brand:#60a5fa; --accent:#22d3ee;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin:0; background: radial-gradient(1200px 600px at 70% -10%, #0a1a3a55, transparent), var(--bg);
      color: var(--ink); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      min-height:100dvh; display:flex; align-items:center; justify-content:center; padding:32px;
    }}
    .wrap {{ width: 100%; max-width: 920px; }}
    .brand {{ text-align:center; margin-bottom:22px; }}
    .brand h1 {{
      margin:0; font-size: clamp(26px, 4vw, 40px); letter-spacing: .5px;
      background: linear-gradient(90deg, var(--brand), var(--accent));
      -webkit-background-clip: text; background-clip: text; color: transparent; font-weight: 800;
    }}
    .brand .sub {{ color: var(--muted); margin-top:6px; font-size: 13px; }}

    .terminal {{
      background: linear-gradient(180deg, #0b1024, #0b1221);
      border: 1px solid #1f2a44; border-radius: 14px;
      box-shadow: 0 30px 80px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.04);
      padding: 20px;
    }}
    .titlebar {{ display:flex; align-items:center; gap:8px; margin-bottom:14px; color:#93b5ff; font-size:12px; }}
    .dot {{ width:10px; height:10px; border-radius:50%; background:#ef4444; box-shadow: 16px 0 0 #f59e0b, 32px 0 0 #22c55e; }}
    .titlebar .path {{ color:#8ab4ff; }}
    .form {{ display:flex; flex-direction:column; align-items:center; gap:14px; }}
    .cmdbox {{ width:100%; background:#0b1023; border:1px solid #1d2a46; border-radius:12px; padding:16px; }}
    .promptline {{ display:flex; align-items:center; justify-content:center; gap:10px; color:#a7f3d0; margin-bottom:10px; font-size:14px; }}
    .promptline .host {{ color:#93c5fd; }}
    input.cmd {{
      width:100%; text-align:center; background: transparent; border: none; outline: none;
      color: #e6eef8; font-size: clamp(16px, 2.4vw, 20px); caret-color: var(--brand); padding: 6px 2px;
    }}
    .actions {{ display:flex; justify-content:center; gap:10px; }}
    .btn {{
      appearance:none; border:none; cursor:pointer;
      background: linear-gradient(90deg, var(--brand), var(--accent));
      color:#0b1020; font-weight:700; letter-spacing:.4px;
      padding:10px 16px; border-radius:10px; transition: transform .06s ease;
    }}
    .btn:active {{ transform: translateY(1px); }}
    .help {{ color:var(--muted); font-size:12px; text-align:center; margin-top:8px; }}
    .disclaimer {{ color:#fca5a5; font-size:12px; text-align:center; margin-top:6px; }}
    footer {{ color:#7c8aa0; font-size:12px; text-align:center; margin-top:18px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="brand">
      <h1>{{{{ scanner_name }}}}</h1>
      <div class="sub">Defensive, permission-based network checks — educational use only</div>
    </div>

    <div class="terminal">
      <div class="titlebar"><span class="dot"></span><span class="path">~/scanner</span></div>
      <form class="form" method="post" action="{{{{ url_for('scan') }}}}">
        <div class="cmdbox">
          <div class="promptline"><span class="user">you@scanner</span><span class="host">~$</span><span>scan &lt;host or IPv4&gt;</span></div>
          <input class="cmd" name="target" placeholder="example.com   |   192.0.2.1" autofocus>

          
  <!-- THE OPTIONS ROW WITH CHECKBOXES -->
  <div class="actions">
    <div class="opts">
      <label><input type="checkbox" name="run_nmap"> Run Nmap (slower)</label>
      <label><input type="checkbox" name="run_nikto"> Run Nikto (slowest)</label>
    </div>
  </div>
        </div>
        <div class="actions">
          <button class="btn" type="submit">Run scan</button>
        </div>
        <div class="help">Installs detected: nmap / nikto (optional). We only do safe, non-exploitative probes.</div>
        <div class="disclaimer">Scan only systems you own or have explicit permission to test.</div>
      </form>
    </div>

    <footer>{{{{ scanner_name }}}} &middot; Flask UI</footer>
  </div>
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
    body { font-family: Arial, Helvetica, sans-serif; background:#0b1220; color:#e6eef8; padding:26px; }
    .brand { text-align:center; margin-bottom:18px; }
    .brand h1 { margin:0; font-size:28px; background: linear-gradient(90deg,#60a5fa,#22d3ee); -webkit-background-clip:text; background-clip:text; color:transparent; }
    .brand .muted { color:#9fb1c7; font-size:12px; margin-top:6px; }
    .card { background:#0f172a; border:1px solid #1f2a44; border-radius:12px; box-shadow:0 10px 40px rgba(0,0,0,.35); padding:18px; margin-bottom:14px; }
    h2 { margin:0 0 10px 0; font-size:18px; color:#bfe1ff; }
    h3 { margin:4px 0 8px; color:#c2e7ff; }
    pre { background:#0b1120;color:#dbeafe;padding:12px;border-radius:8px;overflow:auto; }
    table { width:100%; border-collapse:collapse; }
    td, th { padding:8px; border-bottom:1px solid #1e2b4a; text-align:left; vertical-align:top; }
    .open { color:#34d399; font-weight:600; }
    .closed { color:#94a3b8; }
    .muted { color:#9fb1c7; font-size:13px; }
    .json { font-family: monospace; font-size:13px; background:#0b1221; color:#d6e7ff; padding:10px; border-radius:8px; overflow:auto; }
    .btn-back { display:inline-block; margin-bottom:12px; padding:8px 10px; background:#2563eb; color:white; border-radius:8px; text-decoration:none; }
  </style>
</head>
<body>
  <div class="brand">
    <h1>{{ scanner_name }}</h1>
    <div class="muted">Report for <strong>{{ target }}</strong> &middot; scanned at {{ scanned_at }}</div>
  </div>

  <a class="btn-back" href="{{ url_for('index') }}">&larr; New scan</a>

  <div class="card">
    <h2>Scan summary</h2>
    <p><strong>Resolved IP:</strong> {{ report.resolved_ip or 'N/A' }} {% if report.reverse_dns %}(<em>{{ report.reverse_dns }}</em>){% endif %}</p>
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
    <h2>Ports & banners</h2>
    <table>
      <thead><tr><th style="width:80px">Port</th><th style="width:80px">Status</th><th style="width:100px">RTT (s)</th><th>Banner / Notes</th></tr></thead>
      <tbody>
      {% for port, v in report.ports|dictsort %}
        <tr>
          <td>{{ port }}</td>
          <td>{% if v.open %}<span class="open">open</span>{% else %}<span class="closed">closed</span>{% endif %}</td>
          <td>{{ v.rtt_s or '-' }}</td>
          <td><pre style="white-space:pre-wrap">{{ v.banner or '' }}</pre></td>
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
    <h2>HTTP headers (if reachable)</h2>
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
    <h2>Nmap (optional)</h2>
    {% if report.nmap %}
      {% if report.nmap.available %}
        <p class="muted">Method: {{ report.nmap.method }}</p>
        <pre class="json">{{ report.nmap.raw | tojson(indent=2) }}</pre>
      {% else %}
        <p class="muted">Nmap not available: {{ report.nmap.error }}</p>
      {% endif %}
    {% else %}
      <p class="muted">Nmap not run.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>Nikto (optional)</h2>
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
      <p class="muted">Nikto not run.</p>
    {% endif %}
  </div>

  <div class="card">
    <h2>Recommendations</h2>
    <ul>
      {% for r in report.recommendations %}
        <li>{{ r }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>Raw JSON</h2>
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
    return render_template_string(INDEX_HTML, scanner_name=SCANNER_NAME)

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
    # Nmap (optional; can be slow)
    try:
        if run_nmap_flag:
          report['nmap'] = run_nmap_scan(ip, COMMON_PORTS, timeout=NMAP_TIMEOUT)
        else:
          report['nmap'] = None
    except Exception as e:
      report['nmap_error'] = str(e)


    # Nikto (optional)
    # Nikto (optional; slowest)
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

    # Compute open ports for the template (avoid Jinja 'do' extension)
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
    # Set debug=True while developing to see tracebacks in the terminal
    app.run(host='127.0.0.1', port=5000, debug=True)
