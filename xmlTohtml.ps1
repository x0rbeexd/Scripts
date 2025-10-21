<#
.SYNOPSIS
  Convert Nmap XML output to a readable HTML report.

.EXAMPLE
  .\NmapXmlToHtml.ps1 -XmlFile .\allports.xml -Out .\nmap-report.html
#>

param(
    [Parameter(Mandatory=$true)][string]$XmlFile,
    [Parameter(Mandatory=$false)][string]$Out = "nmap-report.html",
    [switch]$IncludePortsSummary
)

if (-not (Test-Path $XmlFile)) {
    Write-Error "XML file not found: $XmlFile"
    exit 1
}

[xml]$xml = Get-Content -Path $XmlFile -Raw

$hosts = @()
foreach ($host in $xml.nmaprun.host) {
    # Get address (prefer ipv4)
    $addr = ($host.address | Where-Object { $_.addrtype -eq 'ipv4' } | Select-Object -First 1).addr
    if (-not $addr) { $addr = ($host.address | Select-Object -First 1).addr }
    $status = ($host.status).state
    $hostnames = @()
    if ($host.hostnames -and $host.hostnames.hostname) {
        foreach ($hn in @($host.hostnames.hostname)) {
            if ($hn.name) { $hostnames += $hn.name }
        }
    }
    $os = ""
    if ($host.os) {
        if ($host.os.osmatch) { $os = ($host.os.osmatch | Select-Object -First 1).name }
    }

    $ports = @()
    if ($host.ports -and $host.ports.port) {
        foreach ($p in @($host.ports.port)) {
            $portid = [int]$p.portid
            $protocol = $p.protocol
            $state = $p.state.state
            $serviceName = ""
            $serviceProd = ""
            $serviceVer = ""
            if ($p.service) {
                $serviceName = $p.service.name
                $serviceProd = $p.service.product
                $serviceVer  = $p.service.version
            }
            # collect port-level scripts output
            $portScripts = @()
            if ($p.script) {
                foreach ($s in @($p.script)) {
                    $portScripts += @{
                        id = $s.id
                        output = $s.output
                    }
                }
            }
            $ports += @{
                Port = $portid
                Proto = $protocol
                State = $state
                Service = $serviceName
                Product = $serviceProd
                Version = $serviceVer
                Scripts = $portScripts
            }
        }
    }

    # host-level scripts
    $hostScripts = @()
    if ($host.hostscript -and $host.hostscript.script) {
        foreach ($hs in @($host.hostscript.script)) {
            $hostScripts += @{
                id = $hs.id
                output = $hs.output
            }
        }
    }

    $hosts += @{
        Address = $addr
        Status = $status
        Hostnames = ($hostnames -join ", ")
        OS = $os
        Ports = $ports
        HostScripts = $hostScripts
    }
}

# Build summary if requested
$summary = @{}
if ($IncludePortsSummary) {
    foreach ($h in $hosts) {
        foreach ($p in $h.Ports) {
            if ($p.State -eq 'open') {
                $key = "{0}/{1}" -f $p.Port, $p.Proto
                if (-not $summary.ContainsKey($key)) { $summary[$key] = @() }
                $summary[$key] += $h.Address
            }
        }
    }
}

# HTML header + simple CSS
$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset='utf-8'>
<title>Nmap Report - $(Split-Path $XmlFile -Leaf)</title>
<style>
body { font-family: Arial, Helvetica, sans-serif; background:#f8f9fb; color:#222; }
.container { width: 95%; margin: 10px auto; }
h1 { color:#1a73e8; }
.host { background: #fff; border: 1px solid #ddd; padding: 12px; margin: 12px 0; border-radius:6px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 6px; border-bottom: 1px solid #eee; }
th { background: #f1f3f4; }
.badge { padding: 3px 8px; border-radius: 4px; font-weight:600; color:#fff; }
.open { background: #198754; }
.closed { background: #6c757d; }
.filtered { background: #ffb703; color:#111; }
.summary { background: #fff; padding:12px; border:1px solid #ddd; border-radius:6px; margin-bottom:12px;}
.code { font-family: Consolas, monospace; white-space: pre-wrap; background:#f4f6f8; padding:8px; border-radius:4px; border:1px solid #e8eaed; }
</style>
</head>
<body>
<div class='container'>
<h1>Nmap Report: $(Split-Path $XmlFile -Leaf)</h1>
<div class='summary'>
<p><strong>Scanned hosts:</strong> $($hosts.Count)</p>
"@

if ($IncludePortsSummary -and $summary.Keys.Count -gt 0) {
    $html += "<h3>Ports summary</h3><table><tr><th>Port/Proto</th><th>Hosts (count)</th></tr>"
    foreach ($k in $summary.Keys | Sort-Object {[int]($_.Split('/')[0])}) {
        $hostsList = ($summary[$k] | Sort-Object) -join ", "
        $html += "<tr><td>$k</td><td>$($summary[$k].Count) — <span class='code'>$hostsList</span></td></tr>"
    }
    $html += "</table>"
}

$html += "</div>"

# per-host sections
foreach ($h in $hosts) {
    $html += "<div class='host'>"
    $html += "<h2>$($h.Address) <small style='color:#666'>($($h.Hostnames))</small></h2>"
    $html += "<p><strong>Status:</strong> $($h.Status) &nbsp; | &nbsp; <strong>OS:</strong> $([string]::IsNullOrEmpty($h.OS) ? 'n/a' : $h.OS)</p>"

    # Host scripts
    if ($h.HostScripts.Count -gt 0) {
        $html += "<h4>Host scripts</h4>"
        foreach ($hs in $h.HostScripts) {
            $html += "<div><strong>$($hs.id)</strong><div class='code'>$($hs.output)</div></div>"
        }
    }

    # Ports table
    if ($h.Ports.Count -gt 0) {
        $html += "<h4>Ports</h4>"
        $html += "<table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Product/Version</th><th>Scripts</th></tr>"
        foreach ($p in ($h.Ports | Sort-Object -Property Port)) {
            $stateClass = switch ($p.State) { 'open' { 'open' } 'closed' { 'closed' } default { 'filtered' } }
            $svc = if ($p.Service) { $p.Service } else { "&mdash;" }
            $prod = if ($p.Product -or $p.Version) { "{0} {1}" -f $p.Product, $p.Version } else { "&mdash;" }
            $scriptsHtml = ""
            if ($p.Scripts.Count -gt 0) {
                foreach ($s in $p.Scripts) {
                    $scriptsHtml += "<div><strong>$($s.id)</strong><div class='code'>$($s.output)</div></div>"
                }
            } else { $scriptsHtml = "&mdash;" }

            $html += "<tr><td>$($p.Port)</td><td>$($p.Proto)</td><td><span class='badge $stateClass'>$($p.State)</span></td><td>$svc</td><td>$prod</td><td>$scriptsHtml</td></tr>"
        }
        $html += "</table>"
    } else {
        $html += "<p><em>No ports found in XML for this host.</em></p>"
    }

    $html += "</div>" # host
}

$html += @"
</div>
</body>
</html>
"@

# Write file
Set-Content -Path $Out -Value $html -Force -Encoding UTF8
Write-Host "Report written to $Out"
