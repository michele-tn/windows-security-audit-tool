from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import platform
import re
import subprocess
import textwrap
from datetime import datetime, timezone
from pathlib import Path

POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

def normalize_data(value: object) -> object:
    """Simplify nested PowerShell objects into readable JSON primitives."""
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

def run_powershell(script: str, timeout_seconds: int = 45) -> dict[str, object]:
    """Run a PowerShell query in the background and parse its JSON output."""
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
        return {"status": "timeout", "error": f"Timeout after {timeout_seconds}s"}
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
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"status": "ok", "data": lines}

def collect_audit() -> dict[str, object]:
    """Collect non-secret system, network, user, and AD domain metadata in parallel."""
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
                PowerShellLanguageMode = $ExecutionContext.SessionState.LanguageMode
            }
        """,
        "network_adapters": """
            Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
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
        "active_sessions": """
            query user 2>&1
        """,
        "local_administrators": """
            $groupName = (Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop).Name
            try {
                Get-LocalGroupMember -Name $groupName -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name
                        ObjectClass = $_.ObjectClass
                        PrincipalSource = [string]$_.PrincipalSource
                        SID = $_.SID.Value
                    }
                }
            } catch {
                $adsiGroup = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $groupName)
                @($adsiGroup.psbase.Invoke('Members')) | ForEach-Object {
                    $member = $_
                    try {
                        $memberType = $member.GetType()
                        $name = $memberType.InvokeMember('Name', 'GetProperty', $null, $member, $null)
                        $class = $memberType.InvokeMember('Class', 'GetProperty', $null, $member, $null)
                        $adsPath = $memberType.InvokeMember('AdsPath', 'GetProperty', $null, $member, $null)
                        $sidBytes = $memberType.InvokeMember('objectSid', 'GetProperty', $null, $member, $null)
                        $sid = if ($sidBytes) {
                            (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                        } else { $null }
                        [pscustomobject]@{
                            Name = if ($adsPath) { $adsPath -replace '^WinNT://', '' } else { $name }
                            ObjectClass = $class
                            PrincipalSource = 'ADSI fallback'
                            SID = $sid
                        }
                    } catch {
                        [pscustomobject]@{
                            Name = 'Unresolved member'
                            ObjectClass = 'Unknown'
                            PrincipalSource = 'ADSI fallback'
                            SID = $null
                        }
                    }
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
        "privilege_escalation_checks": """
            $always_hklm = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
            $always_hkcu = Get-ItemProperty -Path "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
            $unquoted = Get-CimInstance Win32_Service | Where-Object {$_.BinaryPathName -notlike '"*' -and $_.BinaryPathName -like '* *' -and $_.BinaryPathName -notlike '*C:\\Windows*'} | Select-Object Name, DisplayName, BinaryPathName
            
            [pscustomobject]@{
                AlwaysInstallElevated_HKLM = if ($always_hklm) { $always_hklm.AlwaysInstallElevated } else { 0 }
                AlwaysInstallElevated_HKCU = if ($always_hkcu) { $always_hkcu.AlwaysInstallElevated } else { 0 }
                UnquotedServicePaths = @($unquoted)
            }
        """,
        "local_password_policy": """
            net.exe accounts 2>&1
        """,
        "domain_controllers": """
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object {
                    [pscustomobject]@{
                        Name = $_.Name
                        IPAddress = $_.IPAddress
                        OSVersion = $_.OSVersion
                    }
                }
            } catch {
                "The computer is not joined to an Active Directory domain, or no domain controller is reachable."
            }
        """,
        "domain_administrators": """
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw 'The ActiveDirectory module is not installed (RSAT).'
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
                throw 'The ActiveDirectory module is not installed (RSAT).'
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
                throw 'The ActiveDirectory module is not installed (RSAT).'
            }
            Import-Module ActiveDirectory
            Get-ADDefaultDomainPasswordPolicy |
                Select-Object ComplexityEnabled, LockoutDuration,
                    LockoutObservationWindow, LockoutThreshold, MaxPasswordAge,
                    MinPasswordAge, MinPasswordLength, PasswordHistoryCount,
                    ReversibleEncryptionEnabled
        """,
        "domain_computers_list": """
            try {
                $searcher = [adsisearcher]"objectCategory=computer"
                $searcher.PageSize = 1000
                $searcher.FindAll() | ForEach-Object { $_.Properties.name }
            } catch {
                @()
            }
        """,
        "domain_administrators_adsi": """
            try {
                $searcher = [adsisearcher]"(&(objectCategory=group)(name=Domain Admins))"
                $group = $searcher.FindOne()
                if ($group) {
                    $group.Properties.member | ForEach-Object {
                        $dn = $_
                        $userSearcher = [adsisearcher]"(distinguishedName=$dn)"
                        $user = $userSearcher.FindOne()
                        if ($user) {
                            [pscustomobject]@{
                                SamAccountName = $user.Properties.samaccountname
                                Name = $user.Properties.name
                                DN = $dn
                            }
                        }
                    }
                }
            } catch {
                "Unable to enumerate Domain Admins through ADSI."
            }
        """
    }

    results = {}
    print(f"[*] Starting {len(queries)} audit modules in parallel...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(queries)) as executor:
        future_to_key = {
            executor.submit(run_powershell, script): key for key, script in queries.items()
        }
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                res = future.result()
                if res["status"] == "ok":
                    results[key] = res["data"]
                else:
                    results[key] = {"error": res.get("error", "Unknown error")}
            except Exception as e:
                results[key] = {"error": str(e)}
            print(f" [+] Module '{key}' completed.")
            
    ordered_results = {key: results[key] for key in queries}
    ordered_results["_commands"] = {
        key: textwrap.dedent(script).strip() for key, script in queries.items()
    }
    return ordered_results

SECTION_LABELS = {
    "system": "System information",
    "network_adapters": "Network adapters and configuration",
    "default_routes": "Default routes",
    "listening_ports": "Listening TCP ports",
    "firewall_profiles": "Windows Firewall profiles",
    "active_sessions": "User and RDP sessions",
    "local_administrators": "Local administrators",
    "local_users_password_metadata": "Local user password metadata",
    "privilege_escalation_checks": "Privilege escalation checks",
    "local_password_policy": "Local account policy",
    "domain_controllers": "Detected domain controllers",
    "domain_administrators": "Domain administrators (AD module)",
    "domain_admin_password_metadata": "Domain Admin password metadata",
    "domain_password_policy": "Domain password policy",
    "domain_computers_list": "Active Directory assets",
    "domain_administrators_adsi": "Domain Admin members",
}


def format_report_value(value: object) -> str:
    """Convert a normalized value into safe, scannable HTML."""
    value = normalize_data(value)
    if value is None or value == "":
        return '<span class="muted">Not available</span>'
    if isinstance(value, bool):
        css_class, label = ("yes", "Yes") if value else ("no", "No")
        return f'<span class="boolean {css_class}">{label}</span>'
    if isinstance(value, list):
        if not value:
            return '<span class="muted">No items</span>'
        return '<div class="chips">' + "".join(
            f'<span class="chip">{format_report_value(item)}</span>' for item in value
        ) + "</div>"
    if isinstance(value, dict):
        encoded = html.escape(json.dumps(value, ensure_ascii=False, default=str))
        return f'<details class="raw-object"><summary>Show details</summary><code>{encoded}</code></details>'
    text = str(value)
    escaped = html.escape(text).replace("\n", "<br>")
    if len(text) >= 28 or text.startswith("S-1-"):
        attribute = html.escape(text, quote=True)
        return f'<span class="copy-value"><code>{escaped}</code><button type="button" data-copy="{attribute}" aria-label="Copy value">Copy</button></span>'
    return escaped


def render_report_data(value: object) -> str:
    """Render report collections and objects as tables or badge groups."""
    value = normalize_data(value)
    if isinstance(value, list):
        if not value:
            return '<p class="empty">No items detected.</p>'
        if all(isinstance(item, dict) for item in value):
            rows_data = [item for item in value if isinstance(item, dict)]
            columns = list(dict.fromkeys(key for item in rows_data for key in item))
            headings = "".join(f'<th scope="col">{html.escape(str(column))}</th>' for column in columns)
            rows = "".join(
                f'<tr data-search="{html.escape(json.dumps(item, ensure_ascii=False, default=str), quote=True).lower()}">'
                + "".join(f"<td>{format_report_value(item.get(column))}</td>" for column in columns)
                + "</tr>" for item in rows_data
            )
            return f'<div class="table-wrap"><table class="data-table"><thead><tr>{headings}</tr></thead><tbody>{rows}</tbody></table></div>'
        return '<div class="chips">' + "".join(f'<span class="chip">{format_report_value(item)}</span>' for item in value) + "</div>"
    if isinstance(value, dict):
        rows = "".join(
            f'<tr data-search="{html.escape(str(key) + " " + str(item), quote=True).lower()}">'
            f'<th scope="row">{html.escape(str(key))}</th><td>{format_report_value(item)}</td></tr>'
            for key, item in value.items()
        )
        return f'<div class="table-wrap"><table class="kv data-table"><tbody>{rows}</tbody></table></div>'
    return f"<p>{format_report_value(value)}</p>"


def render_password_policy(value: object) -> str:
    """Render the textual output of ``net accounts`` as a key-value table."""
    lines = value if isinstance(value, list) else str(value or "").splitlines()
    rows: list[str] = []
    for raw_line in lines:
        line = str(raw_line).strip()
        if not line:
            continue
        label, separator, field_value = line.partition(":")
        if not separator:
            continue
        searchable = html.escape(line, quote=True).lower()
        rows.append(
            f'<tr data-search="{searchable}"><th scope="row">{html.escape(label.strip())}</th>'
            f'<td>{format_report_value(field_value.strip())}</td></tr>'
        )
    if not rows:
        return render_report_data(value)
    return f'<div class="table-wrap"><table class="kv data-table"><tbody>{"".join(rows)}</tbody></table></div>'


def render_active_sessions(value: object) -> str:
    """Parse the fixed-width table produced by ``query user``."""
    lines = [str(line).strip() for line in (value if isinstance(value, list) else str(value or "").splitlines()) if str(line).strip()]
    if len(lines) < 2:
        return render_report_data(value)
    headers = ["Username", "Session name", "ID", "State", "Idle time", "Logon time"]
    rows: list[str] = []
    for line in lines[1:]:
        cells = re.split(r"\s{2,}", line.lstrip(">"))
        if len(cells) < len(headers):
            cells = line.lstrip(">").split(maxsplit=len(headers) - 1)
        cells += [""] * (len(headers) - len(cells))
        rows.append(
            f'<tr data-search="{html.escape(line, quote=True).lower()}">'
            + "".join(f"<td>{format_report_value(cell)}</td>" for cell in cells[:len(headers)])
            + "</tr>"
        )
    headings = "".join(f'<th scope="col">{html.escape(header)}</th>' for header in headers)
    return f'<div class="table-wrap"><table class="data-table"><thead><tr>{headings}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def render_domain_assets(value: object) -> str:
    """Explain and present the computers registered in Active Directory."""
    assets = value if isinstance(value, list) else []
    if not assets:
        return render_report_data(value)
    rows = "".join(
        f'<tr data-search="{html.escape(str(asset), quote=True).lower()}"><td>{index}</td>'
        f'<td><code>{html.escape(str(asset))}</code></td></tr>'
        for index, asset in enumerate(assets, start=1)
    )
    return (
        '<div class="explanation"><strong>What this output represents</strong>'
        '<p>Each row is the name of a computer object registered in Active Directory. '
        'The list describes the domain inventory, but does not confirm that the device is powered on, '
        'reachable, or still in use.</p>'
        f'<span class="asset-total">Total computer objects: <strong>{len(assets)}</strong></span></div>'
        '<div class="table-wrap"><table class="data-table asset-table"><thead><tr>'
        '<th scope="col">#</th><th scope="col">Computer name in AD</th>'
        f'</tr></thead><tbody>{rows}</tbody></table></div>'
    )


def render_command(command: object) -> str:
    """Show the command used to produce a section in a collapsible panel."""
    if not command:
        return ""
    return (
        '<details class="command"><summary>PowerShell command executed</summary>'
        f'<pre><code>{html.escape(str(command))}</code></pre></details>'
    )


def generate_html_report(data: dict[str, object], output_path: Path) -> None:
    """Generate an accessible, interactive, self-contained HTML5 dashboard."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    system_info = data.get("system", {}) if isinstance(data.get("system"), dict) else {}
    commands = data.get("_commands", {}) if isinstance(data.get("_commands"), dict) else {}
    report_sections = [(name, value) for name, value in data.items() if name != "_commands"]
    host = html.escape(str(system_info.get("ComputerName", platform.node()) or platform.node()))
    current_user = html.escape(str(system_info.get("CurrentUser", "Not available")))
    cards: list[str] = []
    navigation: list[str] = []
    issue_count = 0

    for index, (name, section_data) in enumerate(report_sections):
        has_error = isinstance(section_data, dict) and "error" in section_data
        status = "error" if has_error else "ok"
        issue_count += int(has_error)
        label = SECTION_LABELS.get(name, name.replace("_", " ").title())
        section_id = f"section-{index}"
        status_label = "Error" if has_error else "Completed"
        if has_error:
            body = f'<div class="notice">{format_report_value(section_data.get("error"))}</div>'
        elif name == "local_password_policy":
            body = render_password_policy(section_data)
        elif name == "active_sessions":
            body = render_active_sessions(section_data)
        elif name == "domain_computers_list":
            body = render_domain_assets(section_data)
        else:
            body = render_report_data(section_data)
        body += render_command(commands.get(name))
        searchable = html.escape(f"{label} {status} {section_data}", quote=True).lower()
        cards.append(
            f'<details class="section-card" id="{section_id}" data-status="{status}" data-search="{searchable}" open>'
            f'<summary><span><small>Section {index + 1:02d}</small><strong>{html.escape(label)}</strong></span>'
            f'<span class="status {status}">{status_label}</span></summary>'
            f'<div class="section-content">{body}</div></details>'
        )
        navigation.append(
            f'<a href="#{section_id}" data-status="{status}"><span>{html.escape(label)}</span><i class="dot {status}"></i></a>'
        )

    completed = len(report_sections) - issue_count
    html_content = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Advanced Windows &amp; AD Audit — {host}</title><style>
:root{{--navy:#101828;--blue:#175cd3;--cyan:#0e9384;--bg:#f5f7fb;--card:#fff;--text:#182230;--muted:#667085;--line:#e4e7ec;--ok:#067647;--okbg:#ecfdf3;--warn:#b54708;--warnbg:#fffaeb;--bad:#b42318;--badbg:#fef3f2}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,sans-serif}}button,input{{font:inherit}}a{{color:inherit}}.hero{{background:radial-gradient(circle at 85% 20%,#18a999 0,transparent 30%),linear-gradient(135deg,#0b1f3a,#175cd3);color:#fff;padding:38px max(24px,calc((100vw - 1500px)/2)) 88px}}.eyebrow{{opacity:.72;text-transform:uppercase;letter-spacing:.12em;font-weight:700;font-size:11px}}h1{{margin:6px 0 7px;font-size:clamp(30px,4vw,48px);letter-spacing:-.04em}}.hero p{{margin:0;opacity:.8}}.shell{{width:min(1500px,calc(100% - 28px));margin:-54px auto 40px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:18px;align-items:start}}.sidebar,.toolbar,.metric,.section-card{{background:var(--card);border:1px solid rgba(16,24,40,.07);box-shadow:0 8px 30px rgba(16,24,40,.07);border-radius:16px}}.sidebar{{position:sticky;top:14px;padding:15px;max-height:calc(100vh - 28px);overflow:auto}}.sidebar h2{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:4px 8px 10px}}nav a{{display:flex;align-items:center;justify-content:space-between;gap:8px;text-decoration:none;padding:9px 10px;border-radius:9px;color:#344054}}nav a:hover,nav a:focus-visible{{background:#eef4ff;color:var(--blue);outline:none}}.dot{{width:8px;height:8px;border-radius:50%;background:var(--bad)}}.dot.ok{{background:var(--ok)}}.content{{min-width:0}}.summary{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}}.metric{{padding:17px}}.metric span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}}.metric strong{{display:block;margin-top:4px;font-size:20px;overflow-wrap:anywhere}}.toolbar{{padding:12px;display:flex;gap:9px;align-items:center;margin-bottom:12px;position:sticky;top:10px;z-index:5}}.search{{flex:1;min-width:180px;border:1px solid var(--line);border-radius:10px;padding:10px 12px}}.btn{{border:1px solid var(--line);background:#fff;border-radius:9px;padding:9px 11px;cursor:pointer;color:#344054}}.btn:hover,.btn.active{{border-color:#84adff;background:#eef4ff;color:var(--blue)}}.section-card{{margin:12px 0;overflow:hidden;scroll-margin-top:84px}}.section-card[open]{{box-shadow:0 10px 34px rgba(16,24,40,.09)}}.section-card>summary{{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:17px 19px}}.section-card>summary::-webkit-details-marker{{display:none}}.section-card>summary span:first-child{{display:grid}}.section-card>summary small{{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.1em}}.section-card>summary strong{{font-size:17px}}.section-card>summary:focus-visible{{outline:3px solid #84adff;outline-offset:-3px}}.section-content{{border-top:1px solid var(--line);padding:17px 19px}}.status,.boolean{{display:inline-flex;border-radius:999px;padding:4px 9px;font-weight:700;font-size:12px;white-space:nowrap}}.status.ok,.boolean.yes{{color:var(--ok);background:var(--okbg)}}.status.error,.boolean.no{{color:var(--bad);background:var(--badbg)}}.table-wrap{{width:100%;overflow:auto;border:1px solid var(--line);border-radius:11px}}table{{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto}}th,td{{padding:10px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);min-width:115px;max-width:420px;overflow-wrap:break-word}}thead th{{position:sticky;top:0;background:#f8fafc;color:#344054;white-space:nowrap}}tbody tr:hover{{background:#f8fbff}}tbody tr:last-child>*{{border-bottom:0}}.kv th{{width:280px;min-width:210px;background:#f8fafc}}.chips{{display:flex;flex-wrap:wrap;gap:5px}}.chip{{display:inline-flex;background:#f2f4f7;border-radius:7px;padding:3px 7px;max-width:100%}}code{{font-family:"Cascadia Mono",Consolas,monospace;font-size:12px;word-break:break-all}}.copy-value{{display:flex;align-items:flex-start;gap:7px;min-width:180px}}.copy-value button{{border:0;background:#eef4ff;color:var(--blue);border-radius:6px;padding:3px 7px;cursor:pointer;white-space:nowrap}}.raw-object code{{display:block;margin-top:6px;padding:9px;background:#f8fafc;border-radius:7px}}.notice{{padding:12px 14px;color:var(--bad);background:var(--badbg);border-radius:9px}}.explanation{{margin-bottom:14px;padding:14px 16px;border:1px solid #b2ddff;background:#eff8ff;border-radius:11px;color:#1849a9}}.explanation p{{margin:5px 0 10px;color:#344054}}.asset-total{{display:inline-flex;padding:5px 10px;border-radius:999px;background:#d1e9ff}}.asset-table th:first-child,.asset-table td:first-child{{width:64px;min-width:64px}}.command{{margin-top:16px;border-top:1px solid var(--line);padding-top:13px}}.command>summary{{cursor:pointer;color:var(--blue);font-weight:700}}.command pre{{margin:10px 0 0;padding:13px;background:#101828;color:#f2f4f7;border-radius:9px;overflow:auto;white-space:pre-wrap}}.command pre code{{word-break:normal}}.muted,.empty{{color:var(--muted)}}[hidden]{{display:none!important}}footer{{text-align:center;color:var(--muted);padding:0 20px 30px}}
@media(max-width:980px){{.shell{{grid-template-columns:1fr}}.sidebar{{position:static;max-height:none}}nav{{display:flex;overflow:auto}}nav a{{min-width:max-content}}.summary{{grid-template-columns:repeat(2,1fr)}}}}@media(max-width:620px){{.summary{{grid-template-columns:1fr}}.toolbar{{flex-wrap:wrap;position:static}}.search{{flex-basis:100%}}th,td{{min-width:150px}}.kv th{{min-width:130px}}}}@media print{{.hero{{padding:20px}}.shell{{display:block;margin:12px;width:calc(100% - 24px)}}.sidebar,.toolbar{{display:none}}.section-card{{box-shadow:none;break-inside:avoid}}.section-card:not([open])>.section-content{{display:block}}}}
</style></head><body><header class="hero"><span class="eyebrow">Security posture snapshot</span><h1>Advanced Windows &amp; AD Audit</h1><p>Searchable inventory of system, network, identity, and Active Directory data</p></header>
<div class="shell"><aside class="sidebar"><h2>Report index</h2><nav>{''.join(navigation)}</nav></aside><main class="content">
<section class="summary" aria-label="Summary"><div class="metric"><span>Computer</span><strong>{host}</strong></div><div class="metric"><span>Audit user</span><strong>{current_user}</strong></div><div class="metric"><span>Completed</span><strong>{completed}/{len(report_sections)}</strong></div><div class="metric"><span>Needs review</span><strong>{issue_count}</strong></div></section>
<div class="toolbar" role="search"><input class="search" id="search" type="search" placeholder="Search users, IPs, SIDs, ports…" aria-label="Search report"><button class="btn active" data-filter="all">All</button><button class="btn" data-filter="ok">Completed</button><button class="btn" data-filter="issues">Issues</button><button class="btn" id="toggle">Collapse</button></div>
<div id="sections">{''.join(cards)}</div></main></div><footer>Generated on {html.escape(generated)} · Standalone HTML5 report</footer>
<script>
const cards=[...document.querySelectorAll('.section-card')],search=document.querySelector('#search');let filter='all';
function apply(){{const q=search.value.trim().toLowerCase();cards.forEach(c=>{{const status=c.dataset.status,statusOk=filter==='all'||filter==='ok'&&status==='ok'||filter==='issues'&&status!=='ok';const textOk=!q||c.dataset.search.includes(q)||[...c.querySelectorAll('tr')].some(r=>r.dataset.search?.includes(q));c.hidden=!(statusOk&&textOk);if(q&&textOk)c.open=true;}})}}
search.addEventListener('input',apply);document.querySelectorAll('[data-filter]').forEach(b=>b.addEventListener('click',()=>{{filter=b.dataset.filter;document.querySelectorAll('[data-filter]').forEach(x=>x.classList.toggle('active',x===b));apply();}}));
document.querySelector('#toggle').addEventListener('click',e=>{{const expand=cards.some(c=>!c.open&&!c.hidden);cards.filter(c=>!c.hidden).forEach(c=>c.open=expand);e.currentTarget.textContent=expand?'Collapse':'Expand';}});
document.addEventListener('click',async e=>{{const b=e.target.closest('[data-copy]');if(!b)return;try{{await navigator.clipboard.writeText(b.dataset.copy);b.textContent='Copied';setTimeout(()=>b.textContent='Copy',1200)}}catch{{b.textContent='Select'}}}});
</script></body></html>"""
    output_path.write_text(html_content, encoding="utf-8")


def main() -> None:
    """Run the audit and save the results in JSON and HTML formats."""
    parser = argparse.ArgumentParser(description="Advanced Multi-Threaded Windows & AD Auditor")
    parser.add_argument(
        "-o",
        "--output",
        help="Base output path (without extension)",
        default="audit_result",
    )
    args = parser.parse_args()

    if platform.system() != "Windows":
        print("[-] Critical error: this script runs Windows-only queries.")
        return

    print("[*] Initializing the high-density audit suite...")
    audit_data = collect_audit()

    json_output = Path(f"{args.output}.json")
    json_output.write_text(
        json.dumps(audit_data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[+] Raw data export completed: {json_output.resolve()}")

    html_output = Path(f"{args.output}.html")
    generate_html_report(audit_data, html_output)
    print(f"[+] Structured graphical report generated: {html_output.resolve()}")
    print("[*] Operation completed successfully.")


if __name__ == "__main__":
    main()
