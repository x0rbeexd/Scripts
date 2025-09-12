<#
.SYNOPSIS
    findit.ps1 - scan a folder recursively for sensitive files and sensitive strings.

.DESCRIPTION
    Native PowerShell script. Scans directory tree, reports:
      - files with "juicy" extensions (sql, bak, backup, key, pem, pfx, etc.)
      - content matches for sensitive keywords/regexes (password, secret, api_key, token, private key, etc.)
    Very verbose output: prints which folder is being scanned, files checked, matches found.
    Produces an in-memory result set and can export to JSON/CSV.

.USAGE
    PS> .\findit.ps1 -RootPath "C:\repos" -Verbose
    PS> .\findit.ps1 -RootPath . -ExportJson results.json -ExportCsv results.csv

.PARAMETER RootPath
    Path to the root folder to scan. Mandatory.

.PARAMETER IncludeExtensions
    Optional array of file extensions to always flag (dot included). Default includes many common backup/dump/key extensions.

.PARAMETER SearchPatterns
    Optional array of regex patterns (PowerShell regex) to search file contents for. Default set included.

.PARAMETER MaxDepth
    Optional maximum recursion depth (0 = only root folder). Default: [no limit].

.PARAMETER ExportJson
    Optional path to write JSON results.

.PARAMETER ExportCsv
    Optional path to write CSV results.

.EXAMPLE
    .\findit.ps1 -RootPath "C:\projects" -ExportCsv "C:\temp\findings.csv"

.NOTES
    - Uses only built-in cmdlets (Get-ChildItem, Select-String, etc.)
    - Designed to be noisy/verbose for audit-style review.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$RootPath,

    [string[]]$IncludeExtensions = @(
        ".sql", ".bak", ".backup", ".back", ".ldf", ".mdf",
        ".sql.gz", ".sql.zip", ".zip", ".7z", ".tar", ".tgz",
        ".key", ".pem", ".pfx", ".crt", ".cer", ".der",
        ".mdb", ".db", ".sqlite", ".s3db", ".dump"
    ),

    [string[]]$SearchPatterns = @(
        "password",
        "passwd",
        "\bpwd\b",
        "secret",
        "api[_-]?key",
        "apikey",
        "token",
        "bearer",
        "aws_access_key_id",
        "aws_secret_access_key",
        "private\s*key",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "ssh-rsa",
        "connectionstring",
        "connection\s*string",
        "dsn=",
        "jdbc:",
        "mongo(conn|uri)",
        "password\s*=",
        "pass\s*:",
        "pwd\s*:",
        "secret_key",
        "auth_token",
        "authorization\s*:\s*Bearer",
        "client_secret",
        "client_id",
        "access_token",
        "refresh_token",
        "X-Api-Key",
        "X-API-KEY",
        "smtp_password",
        "db_password"
    ),

    [int]$MaxDepth = [int]::MaxValue,

    [string]$ExportJson = "",
    [string]$ExportCsv = ""
)

function Write-Status {
    param($Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$ts] $Message"
}

# Normalize root path
try {
    $RootPath = (Resolve-Path -Path $RootPath -ErrorAction Stop).ProviderPath
} catch {
    Write-Error "RootPath '$RootPath' does not exist or cannot be resolved."
    exit 2
}

Write-Status "Starting scan. RootPath = '$RootPath'"
Write-Status "Extensions flagged: $($IncludeExtensions -join ', ')"
Write-Status "Search patterns (regex): $([string]::Join(', ', $SearchPatterns | Select-Object -First 20))"
if ($MaxDepth -ne [int]::MaxValue) { Write-Status "MaxDepth set to $MaxDepth" }

# Prepare regex alternation for Select-String; keep patterns separate to get matched pattern string from Matches
$patternList = $SearchPatterns

# Result collection
$results = [System.Collections.Generic.List[PSObject]]::new()
$totalFiles = 0
$totalMatches = 0
$totalFlaggedExt = 0

# Helper to compute depth
function Get-RelativeDepth($base, $path) {
    $baseParts = (Split-Path -Path $base -Resolve -ErrorAction SilentlyContinue) -split [IO.Path]::DirectorySeparatorChar
    $pathParts = (Split-Path -Path $path -Resolve -ErrorAction SilentlyContinue) -split [IO.Path]::DirectorySeparatorChar
    return ($pathParts.Length - $baseParts.Length)
}

# Walk directories with recursion and depth control
Write-Status "Enumerating files..."
$gciParams = @{
    Path = $RootPath
    Recurse = $true
    File = $true
    ErrorAction = 'SilentlyContinue'
}

# We'll iterate Get-ChildItem results, but filter by depth if MaxDepth specified
try {
    $allFiles = Get-ChildItem @gciParams
} catch {
    Write-Warning "Get-ChildItem failed: $_"
    $allFiles = @()
}

foreach ($file in $allFiles) {
    # file can be null if access denied
    if (-not $file) { continue }
    $relDepth = Get-RelativeDepth -base $RootPath -path $file.DirectoryName
    if ($relDepth -gt $MaxDepth) { continue }

    $totalFiles++
    Write-Host "Scanning folder: $($file.DirectoryName)  (file: $($file.Name))"

    # Check extension flagging first (case-insensitive)
    $ext = $file.Extension
    if ($ext) { $ext = $ext.ToLowerInvariant() }
    $flagByExt = $false
    if ($IncludeExtensions -contains $ext) {
        $flagByExt = $true
        $totalFlaggedExt++
        Write-Host "  [FLAG - extension] $($file.FullName)"
        $results.Add([pscustomobject]@{
            Type = "Extension-Flag"
            Path = $file.FullName
            FileName = $file.Name
            Directory = $file.DirectoryName
            MatchText = $ext
            LineNumber = $null
            MatchedLine = $null
            Timestamp = (Get-Date).ToString("o")
        })
        # continue scanning content below as well to capture embedded secrets inside backups/dumps
    }

    # Attempt to scan file content with Select-String using provided patterns
    # Use -Raw for large lines? Select-String handles streaming; we'll call it directly.
    # Wrap in try/catch to handle permissions and binary unreadable files gracefully.
    try {
        # Select-String over an array of regex patterns; gives MatchInfo objects
        $matches = Select-String -Path $file.FullName -Pattern $patternList -AllMatches -SimpleMatch:$false -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [ERROR] Could not read file (permission / binary): $($file.FullName)"
        continue
    }
    if ($matches) {
        foreach ($m in $matches) {
            $totalMatches++
            $matchedText = $m.Matches | ForEach-Object { $_.Value } | Select-Object -First 1
            Write-Host "  [MATCH] $($file.FullName) : Line $($m.LineNumber) : $matchedText"
            $results.Add([pscustomobject]@{
                Type = "Content-Match"
                Path = $file.FullName
                FileName = $file.Name
                Directory = $file.DirectoryName
                MatchText = $matchedText
                LineNumber = $m.LineNumber
                MatchedLine = $m.Line.Trim()
                Timestamp = (Get-Date).ToString("o")
            })
        }
    } else {
        Write-Host "  [OK] No content matches in file."
    }
}

# Summary
Write-Status "Scan complete."
Write-Status "Total files inspected: $totalFiles"
Write-Status "Total files flagged by extension : $totalFlaggedExt"
Write-Status "Total content matches found: $totalMatches"
Write-Status "Total result objects: $($results.Count)"

# Export results if requested
if ($ExportJson -and $ExportJson.Trim() -ne "") {
    try {
        $outdir = Split-Path -Path $ExportJson -Parent
        if ($outdir -and -not (Test-Path $outdir)) { New-Item -ItemType Directory -Path $outdir -Force | Out-Null }
        $results | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportJson -Encoding UTF8
        Write-Status "Exported results to JSON: $ExportJson"
    } catch {
        Write-Warning "Failed exporting JSON: $_"
    }
}

if ($ExportCsv -and $ExportCsv.Trim() -ne "") {
    try {
        $outdir = Split-Path -Path $ExportCsv -Parent
        if ($outdir -and -not (Test-Path $outdir)) { New-Item -ItemType Directory -Path $outdir -Force | Out-Null }
        $results | Select-Object Type,Path,FileName,Directory,MatchText,LineNumber,MatchedLine,Timestamp | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Status "Exported results to CSV: $ExportCsv"
    } catch {
        Write-Warning "Failed exporting CSV: $_"
    }
}

# Print a short table of results to console (if any)
if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host "=== Findings (summary) ==="
    $results | Select-Object Type, FileName, @{Name="PathShort";Expression={ $_.Path -replace [regex]::Escape($RootPath), "." }}, MatchText, LineNumber | Format-Table -AutoSize
} else {
    Write-Host "No sensitive files or content matches found."
}

# Return results object for possible scripting consumption
return $results
