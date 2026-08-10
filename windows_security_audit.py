from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


POWERSHELL = Path(
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
)


def normalize_data(value: object) -> object:
    """Collapse verbose PowerShell objects into readable JSON primitives."""
    if isinstance(value, list):
        return [normalize_data(item) for item in value]
    if not isinstance(value, dict):
        return value

    if "Value" in value and isinstance(value["Value"], (str, int, float, bool)):
        return normalize_data(value["Value"])
    if "value" in value and isinstance(value["value"], (str, int, float, bool)):
        return normalize_data(value["value"])

    return {
        str(key): normalize_data(item)
        for key, item in value.items()
        if key not in {"BinaryLength", "AccountDomainSid"}
    }


def run_powershell(script: str, timeout_seconds: int = 30) -> dict[str, object]:
    """Run a non-interactive PowerShell audit query and parse its JSON output."""
    command = [
        str(POWERSHELL),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"& {{ $ErrorActionPreference = 'Stop'; {script} }} | ConvertTo-Json -Depth 8 -Compress",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            encoding="utf-8-sig",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"Timeout dopo {timeout_seconds}s"}
    except OSError as error:
        return {"status": "error", "error": str(error)}

    if completed.returncode != 0:
        return {
            "status": "error",
            "exit_code": completed.returncode,
            "error": completed.stderr.strip() or completed.stdout.strip(),
        }

    output = completed.stdout.strip()
    if not output:
        return {"status": "ok", "data": None}

    try:
        return {"status": "ok", "data": normalize_data(json.loads(output))}
    except json.JSONDecodeError:
        return {"status": "error", "error": "Output PowerShell non JSON", "raw": output}


def collect_audit() -> dict[str, object]:
    """Collect non-secret Windows, network, administrator, and password metadata."""
    queries = {
        "system": """
            $computer = Get-CimInstance Win32_ComputerSystem
            $os = Get-CimInstance Win32_OperatingSystem
            [pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Domain = $computer.Domain
                PartOfDomain = $computer.PartOfDomain
                CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                WindowsProduct = $os.Caption
                WindowsVersion = $os.Version
                LastBootTime = $os.LastBootUpTime
            }
        """,
        "network_adapters": """
            Get-NetIPConfiguration | ForEach-Object {
                [pscustomobject]@{
                    InterfaceAlias = $_.InterfaceAlias
                    InterfaceIndex = $_.InterfaceIndex
                    AdapterDescription = $_.NetAdapter.InterfaceDescription
                    Status = $_.NetAdapter.Status
                    MacAddress = $_.NetAdapter.MacAddress
                    IPv4 = @($_.IPv4Address.IPAddress)
                    IPv6 = @($_.IPv6Address.IPAddress)
                    IPv4Gateway = @($_.IPv4DefaultGateway.NextHop)
                    IPv6Gateway = @($_.IPv6DefaultGateway.NextHop)
                    DnsServers = @($_.DNSServer.ServerAddresses)
                }
            }
        """,
        "default_routes": """
            Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue |
                Select-Object InterfaceAlias, InterfaceIndex, DestinationPrefix, NextHop, RouteMetric
        """,
        "listening_ports": """
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Select-Object LocalAddress, LocalPort, OwningProcess |
                Sort-Object LocalPort -Unique
        """,
        "firewall_profiles": """
            Get-NetFirewallProfile |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction,
                    AllowInboundRules, AllowLocalFirewallRules, NotifyOnListen
        """,
        "local_administrators": """
            $group = Get-LocalGroup -SID 'S-1-5-32-544'
            Get-LocalGroupMember -Group $group | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    ObjectClass = $_.ObjectClass
                    PrincipalSource = [string]$_.PrincipalSource
                    SID = $_.SID.Value
                }
            }
        """,
        "local_users_password_metadata": """
            Get-LocalUser | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    LastLogon = $_.LastLogon
                    PasswordLastSet = $_.PasswordLastSet
                    PasswordExpires = $_.PasswordExpires
                    PasswordRequired = $_.PasswordRequired
                    UserMayChangePassword = $_.UserMayChangePassword
                    SID = $_.SID.Value
                }
            }
        """,
        "local_password_policy": """
            $output = net.exe accounts 2>&1
            [pscustomobject]@{ RawPolicy = ($output -join [Environment]::NewLine) }
        """,
        "domain_administrators": """
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'Modulo ActiveDirectory non installato (RSAT).'
            }
            Import-Module ActiveDirectory
            $domainSid = (Get-ADDomain).DomainSID.Value
            $group = Get-ADGroup -Identity ($domainSid + '-512')
            Get-ADGroupMember -Identity $group -Recursive | ForEach-Object {
                [pscustomobject]@{
                    Name = $_.Name
                    SamAccountName = $_.SamAccountName
                    ObjectClass = $_.ObjectClass
                    DistinguishedName = $_.DistinguishedName
                    SID = $_.SID.Value
                }
            }
        """,
        "domain_admin_password_metadata": """
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'Modulo ActiveDirectory non installato (RSAT).'
            }
            Import-Module ActiveDirectory
            $domainSid = (Get-ADDomain).DomainSID.Value
            $group = Get-ADGroup -Identity ($domainSid + '-512')
            Get-ADGroupMember -Identity $group -Recursive |
                Where-Object ObjectClass -eq 'user' |
                ForEach-Object {
                    Get-ADUser -Identity $_.DistinguishedName -Properties Enabled,
                        PasswordLastSet, PasswordExpired, PasswordNeverExpires,
                        CannotChangePassword, LastLogonDate, LockedOut
                } |
                Select-Object Name, SamAccountName, Enabled, PasswordLastSet,
                    PasswordExpired, PasswordNeverExpires, CannotChangePassword,
                    LastLogonDate, LockedOut, DistinguishedName
        """,
        "domain_password_policy": """
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'Modulo ActiveDirectory non installato (RSAT).'
            }
            Import-Module ActiveDirectory
            Get-ADDefaultDomainPasswordPolicy |
                Select-Object ComplexityEnabled, LockoutDuration,
                    LockoutObservationWindow, LockoutThreshold, MaxPasswordAge,
                    MinPasswordAge, MinPasswordLength, PasswordHistoryCount,
                    ReversibleEncryptionEnabled
        """,
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_sections = {
            name: executor.submit(run_powershell, query)
            for name, query in queries.items()
        }
        sections = {
            name: future.result()
            for name, future in future_sections.items()
        }

    return {
        "audit": {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "collector_host": platform.node(),
            "collector_user": os.environ.get("USERNAME"),
            "contains_passwords_or_hashes": False,
            "scope": "Read-only security metadata; no secrets are collected.",
        },
        "sections": sections,
    }


SECTION_LABELS = {
    "system": "Sistema",
    "network_adapters": "Schede di rete",
    "default_routes": "Route predefinite",
    "listening_ports": "Porte in ascolto",
    "firewall_profiles": "Profili firewall",
    "local_administrators": "Amministratori locali",
    "local_users_password_metadata": "Utenti locali e password",
    "local_password_policy": "Policy password locale",
    "domain_administrators": "Amministratori di dominio",
    "domain_admin_password_metadata": "Password amministratori di dominio",
    "domain_password_policy": "Policy password di dominio",
}


def format_value(value: object) -> str:
    """Format a normalized value as compact, safe, scannable HTML."""
    value = normalize_data(value)
    if value is None or value == "":
        return '<span class="muted">Non disponibile</span>'
    if isinstance(value, bool):
        css_class, label = ("yes", "Sì") if value else ("no", "No")
        return f'<span class="boolean {css_class}">{label}</span>'
    if isinstance(value, list):
        if not value:
            return '<span class="muted">Nessun elemento</span>'
        return '<div class="chips">' + "".join(
            f'<span class="chip">{format_value(item)}</span>' for item in value
        ) + "</div>"
    if isinstance(value, dict):
        encoded = html.escape(json.dumps(value, ensure_ascii=False, default=str))
        return f'<details class="raw-object"><summary>Mostra dettagli</summary><code>{encoded}</code></details>'
    text = str(value)
    escaped = html.escape(text).replace("\n", "<br>")
    if len(text) >= 28 or text.startswith("S-1-"):
        attribute = html.escape(text, quote=True)
        return f'<span class="copy-value"><code>{escaped}</code><button type="button" data-copy="{attribute}" aria-label="Copia valore">Copia</button></span>'
    return escaped


def render_object_table(data: dict[str, object]) -> str:
    """Render a dictionary as a two-column semantic table."""
    rows = "".join(
        f'<tr data-search="{html.escape(str(key) + " " + str(value), quote=True).lower()}">'
        f'<th scope="row">{html.escape(str(key))}</th><td>{format_value(value)}</td></tr>'
        for key, value in normalize_data(data).items()
    )
    return f'<div class="table-wrap"><table class="kv data-table"><tbody>{rows}</tbody></table></div>'


def render_section_data(data: object) -> str:
    """Render normalized audit data without recursively expanding objects."""
    data = normalize_data(data)
    if isinstance(data, list):
        if not data:
            return '<p class="empty">Nessun elemento rilevato.</p>'
        if all(isinstance(item, dict) for item in data):
            dictionaries = [item for item in data if isinstance(item, dict)]
            columns = list(dict.fromkeys(key for item in dictionaries for key in item))
            header = "".join(f'<th scope="col">{html.escape(str(column))}</th>' for column in columns)
            rows = "".join(
                f'<tr data-search="{html.escape(json.dumps(item, ensure_ascii=False, default=str), quote=True).lower()}">'
                + "".join(f"<td>{format_value(item.get(column))}</td>" for column in columns)
                + "</tr>" for item in dictionaries
            )
            return f'<div class="table-wrap"><table class="data-table"><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table></div>'
        return '<div class="chips">' + "".join(f'<span class="chip">{format_value(item)}</span>' for item in data) + "</div>"
    if isinstance(data, dict):
        return render_object_table(data)
    return f"<p>{format_value(data)}</p>"


def build_html_report(report: dict[str, object]) -> str:
    """Build an accessible, interactive, standalone HTML5 audit dashboard."""
    audit_data = report.get("audit", {}) if isinstance(report.get("audit"), dict) else {}
    section_data = report.get("sections", {}) if isinstance(report.get("sections"), dict) else {}
    statuses = [section.get("status", "error") for section in section_data.values() if isinstance(section, dict)]
    ok_count, issue_count = statuses.count("ok"), len(statuses) - statuses.count("ok")
    cards, navigation = [], []
    for index, (name, section) in enumerate(section_data.items()):
        result = section if isinstance(section, dict) else {"status": "error", "error": section}
        status = str(result.get("status", "error"))
        label = SECTION_LABELS.get(str(name), str(name).replace("_", " ").title())
        section_id = f"section-{index}"
        status_label = {"ok": "Completata", "timeout": "Timeout"}.get(status, "Errore")
        body = render_section_data(result.get("data")) if status == "ok" else f'<div class="notice">{format_value(result.get("error", "Errore non specificato"))}</div>'
        searchable = html.escape(f"{label} {status} {result}", quote=True).lower()
        cards.append(
            f'<details class="section-card" id="{section_id}" data-status="{html.escape(status)}" data-search="{searchable}" open>'
            f'<summary><span><small>Sezione {index + 1:02d}</small><strong>{html.escape(label)}</strong></span>'
            f'<span class="status {html.escape(status)}">{status_label}</span></summary>'
            f'<div class="section-content">{body}</div></details>'
        )
        navigation.append(f'<a href="#{section_id}" data-status="{html.escape(status)}"><span>{html.escape(label)}</span><i class="dot {html.escape(status)}"></i></a>')

    generated = html.escape(str(audit_data.get("generated_at_utc", "Non disponibile")))
    host = html.escape(str(audit_data.get("collector_host", "Non disponibile")))
    user = html.escape(str(audit_data.get("collector_user", "Non disponibile")))
    return f"""<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Security Audit — {host}</title><style>
:root{{--navy:#101828;--blue:#175cd3;--cyan:#0e9384;--bg:#f5f7fb;--card:#fff;--text:#182230;--muted:#667085;--line:#e4e7ec;--ok:#067647;--okbg:#ecfdf3;--warn:#b54708;--warnbg:#fffaeb;--bad:#b42318;--badbg:#fef3f2}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}}button,input{{font:inherit}}a{{color:inherit}}.hero{{background:radial-gradient(circle at 85% 20%,#18a999 0,transparent 30%),linear-gradient(135deg,#0b1f3a,#175cd3);color:#fff;padding:38px max(24px,calc((100vw - 1500px)/2)) 88px}}.eyebrow{{opacity:.72;text-transform:uppercase;letter-spacing:.12em;font-weight:700;font-size:11px}}h1{{margin:6px 0 7px;font-size:clamp(30px,4vw,48px);letter-spacing:-.04em}}.hero p{{margin:0;opacity:.8}}.shell{{width:min(1500px,calc(100% - 28px));margin:-54px auto 40px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:18px;align-items:start}}.sidebar,.toolbar,.metric,.section-card{{background:var(--card);border:1px solid rgba(16,24,40,.07);box-shadow:0 8px 30px rgba(16,24,40,.07);border-radius:16px}}.sidebar{{position:sticky;top:14px;padding:15px;max-height:calc(100vh - 28px);overflow:auto}}.sidebar h2{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:4px 8px 10px}}nav a{{display:flex;align-items:center;justify-content:space-between;gap:8px;text-decoration:none;padding:9px 10px;border-radius:9px;color:#344054}}nav a:hover,nav a:focus-visible{{background:#eef4ff;color:var(--blue);outline:none}}.dot{{width:8px;height:8px;border-radius:50%;background:var(--bad)}}.dot.ok{{background:var(--ok)}}.dot.timeout{{background:var(--warn)}}.content{{min-width:0}}.summary{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}}.metric{{padding:17px}}.metric span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}}.metric strong{{display:block;margin-top:4px;font-size:20px;overflow-wrap:anywhere}}.toolbar{{padding:12px;display:flex;gap:9px;align-items:center;margin-bottom:12px;position:sticky;top:10px;z-index:5}}.search{{flex:1;min-width:180px;border:1px solid var(--line);border-radius:10px;padding:10px 12px}}.btn{{border:1px solid var(--line);background:#fff;border-radius:9px;padding:9px 11px;cursor:pointer;color:#344054}}.btn:hover,.btn.active{{border-color:#84adff;background:#eef4ff;color:var(--blue)}}.section-card{{margin:12px 0;overflow:hidden;scroll-margin-top:84px}}.section-card[open]{{box-shadow:0 10px 34px rgba(16,24,40,.09)}}.section-card>summary{{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:17px 19px}}.section-card>summary::-webkit-details-marker{{display:none}}.section-card>summary span:first-child{{display:grid}}.section-card>summary small{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em}}.section-card>summary strong{{font-size:17px}}.section-card>summary:focus-visible{{outline:3px solid #84adff;outline-offset:-3px}}.section-content{{border-top:1px solid var(--line);padding:17px 19px}}.status,.boolean{{display:inline-flex;border-radius:999px;padding:4px 9px;font-weight:700;font-size:12px;white-space:nowrap}}.status.ok,.boolean.yes{{color:var(--ok);background:var(--okbg)}}.status.timeout{{color:var(--warn);background:var(--warnbg)}}.status.error,.boolean.no{{color:var(--bad);background:var(--badbg)}}.table-wrap{{width:100%;overflow:auto;border:1px solid var(--line);border-radius:11px}}table{{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto}}th,td{{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);min-width:115px;max-width:420px;overflow-wrap:break-word}}thead th{{position:sticky;top:0;background:#f8fafc;color:#344054;white-space:nowrap}}tbody tr:hover{{background:#f8fbff}}tbody tr:last-child>*{{border-bottom:0}}.kv th{{width:230px;min-width:180px;background:#f8fafc}}.chips{{display:flex;flex-wrap:wrap;gap:5px}}.chip{{display:inline-flex;background:#f2f4f7;border-radius:7px;padding:3px 7px;max-width:100%}}code{{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;word-break:break-all}}.copy-value{{display:flex;align-items:flex-start;gap:7px;min-width:180px}}.copy-value button{{border:0;background:#eef4ff;color:var(--blue);border-radius:6px;padding:3px 7px;cursor:pointer;white-space:nowrap}}.raw-object code{{display:block;margin-top:6px;padding:9px;background:#f8fafc;border-radius:7px}}.notice{{padding:12px 14px;color:var(--bad);background:var(--badbg);border-radius:9px}}.muted,.empty{{color:var(--muted)}}[hidden]{{display:none!important}}footer{{text-align:center;color:var(--muted);padding:0 20px 30px}}
@media(max-width:980px){{.shell{{grid-template-columns:1fr}}.sidebar{{position:static;max-height:none}}nav{{display:flex;overflow:auto}}nav a{{min-width:max-content}}.summary{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:620px){{.summary{{grid-template-columns:1fr}}.toolbar{{flex-wrap:wrap;position:static}}.search{{flex-basis:100%}}th,td{{min-width:150px}}.kv th{{min-width:130px}}}}@media print{{.hero{{padding:20px}}.shell{{display:block;margin:12px;width:calc(100% - 24px)}}.sidebar,.toolbar{{display:none}}.section-card{{box-shadow:none;break-inside:avoid}}.section-card:not([open])>.section-content{{display:block}}}}
</style></head><body><header class="hero"><span class="eyebrow">Security posture snapshot</span><h1>Windows Security Audit</h1><p>Inventario consultabile di rete, identità e policy — nessuna password o hash acquisito</p></header>
<div class="shell"><aside class="sidebar"><h2>Indice del report</h2><nav>{''.join(navigation)}</nav></aside><main class="content">
<section class="summary" aria-label="Riepilogo"><div class="metric"><span>Computer</span><strong>{host}</strong></div><div class="metric"><span>Utente audit</span><strong>{user}</strong></div><div class="metric"><span>Completate</span><strong>{ok_count}/{len(statuses)}</strong></div><div class="metric"><span>Da verificare</span><strong>{issue_count}</strong></div></section>
<div class="toolbar" role="search"><input class="search" id="search" type="search" placeholder="Cerca utenti, IP, SID, porte…" aria-label="Cerca nel report"><button class="btn active" data-filter="all">Tutte</button><button class="btn" data-filter="ok">Completate</button><button class="btn" data-filter="issues">Problemi</button><button class="btn" id="toggle">Comprimi</button></div>
<div id="sections">{''.join(cards)}</div></main></div><footer>Generato il {generated} · Report autonomo HTML5</footer>
<script>
const cards=[...document.querySelectorAll('.section-card')],search=document.querySelector('#search');let filter='all';
function apply(){{const q=search.value.trim().toLowerCase();cards.forEach(c=>{{const status=c.dataset.status,statusOk=filter==='all'||filter==='ok'&&status==='ok'||filter==='issues'&&status!=='ok';const textOk=!q||c.dataset.search.includes(q)||[...c.querySelectorAll('tr')].some(r=>r.dataset.search?.includes(q));c.hidden=!(statusOk&&textOk);if(q&&textOk)c.open=true;}})}}
search.addEventListener('input',apply);document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===b));apply();}}));
document.querySelector('#toggle').addEventListener('click',e=>{{const expand=cards.some(c=>!c.open&&!c.hidden);cards.filter(c=>!c.hidden).forEach(c=>c.open=expand);e.currentTarget.textContent=expand?'Comprimi':'Espandi';}});
document.addEventListener('click',async e=>{{const b=e.target.closest('[data-copy]');if(!b)return;try{{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copiato';setTimeout(()=>b.textContent='Copia',1200)}}catch{{b.textContent='Seleziona'}}}});
</script></body></html>"""

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    parser = argparse.ArgumentParser(
        description="Audit read-only di rete, amministratori e policy password Windows/AD."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(f"windows_security_audit_{timestamp}.json"),
        help="Percorso del report JSON.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Stampa il report anche sullo standard output.",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        help="Percorso del report HTML5; per default usa lo stesso nome del JSON.",
    )
    return parser.parse_args()


def main() -> int:
    """Generate and persist the Windows security audit report."""
    arguments = parse_arguments()
    report = collect_audit()
    if not isinstance(report, dict):
        raise RuntimeError("La raccolta audit non ha restituito un report valido.")
    serialized = json.dumps(report, indent=2, ensure_ascii=False, default=str)
    html_output = arguments.html_output or arguments.output.with_suffix(".html")
    arguments.output.write_text(serialized + "\n", encoding="utf-8")
    html_output.write_text(build_html_report(report), encoding="utf-8")

    if arguments.stdout:
        print(serialized)

    print(f"Report JSON generato: {arguments.output.resolve()}")
    print(f"Report HTML generato: {html_output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
