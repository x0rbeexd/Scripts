[xml]$nmap = Get-Content "output.xml"

$portSummary = @{}

foreach ($h in $nmap.nmaprun.host) {
    $ip = $h.address.addr
    foreach ($port in $h.ports.port) {
        if ($port.state.state -eq "open") {
            $portNum = $port.portid
            if (-not $portSummary.ContainsKey($portNum)) {
                $portSummary[$portNum] = @()
            }
            $portSummary[$portNum] += $ip
        }
    }
}

foreach ($port in $portSummary.Keys) {
    $ips = $portSummary[$port] | Sort-Object -Unique
    Write-Output "Port $port - Open on: $($ips -join ', ')"
}
