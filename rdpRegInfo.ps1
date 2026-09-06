<#
.SYNOPSIS
    Enumerates RDP (Remote Desktop) connection history and related artifacts.

.DESCRIPTION
    Gathers Remote Desktop connection history from several sources and merges
    them into a single, queryable/exportable result set:

      - HKCU:\Software\Microsoft\Terminal Server Client\Servers\*
          One subkey per host ever connected to, with values like UsernameHint.
      - HKCU:\Software\Microsoft\Terminal Server Client\Default
          MRU0, MRU1, ... - the most-recently-used connection targets (typed,
          not necessarily saved as a Servers subkey).
      - Registry key LastWriteTime for every entry above, used as an
          approximate "last seen" timestamp (the registry has no explicit
          connection-time value, but the key's write time is a decent proxy).
      - Saved credentials via `cmdkey /list` for any TERMSRV/<host> target,
          so you can see which hosts have a stored password.
      - The Microsoft-Windows-TerminalServices-RDPClient/Operational event
          log, for actual connection timestamps (higher fidelity than the
          registry write time, when the log is available).
      - Saved .rdp connection files on disk (-IncludeRdpFiles).
      - Other local user profiles (-AllUsers, requires elevation): loads
          each profile's NTUSER.DAT (if not already loaded) read-only, scans
          it the same way, then unloads it.

.PARAMETER IncludeRdpFiles
    Also scan Desktop/Documents/Downloads for saved .rdp files and extract
    the target host / username from each. With -AllUsers, this scans every
    accessible profile's folders instead of just the current user's.

.PARAMETER AllUsers
    Also enumerate RDP history for other local user profiles. Requires an
    elevated (Administrator) PowerShell session; profiles that can't be
    read (e.g. hive locked, access denied) are skipped with a warning.
    Any hive this script loads itself is always unloaded afterwards.

.PARAMETER SkipCredentialCheck
    Skip the `cmdkey /list` cross-reference for saved credentials.

.PARAMETER SkipEventLog
    Skip the RDPClient operational event log lookup (useful if the log is
    huge and you want a fast, registry-only result).

.PARAMETER MaxEvents
    Maximum number of events to pull from the RDPClient event log. Default 500.

.PARAMETER ExportCsv
    Path to write the combined results as CSV.

.PARAMETER ExportJson
    Path to write the combined results as JSON.

.PARAMETER Quiet
    Suppress the console table; useful when you only want the export file(s)
    or want to consume the pipeline output yourself.

.EXAMPLE
    .\rdpRegInfo.ps1

.EXAMPLE
    .\rdpRegInfo.ps1 -IncludeRdpFiles -ExportCsv .\rdp_history.csv

.EXAMPLE
    .\rdpRegInfo.ps1 -AllUsers -ExportJson .\rdp_history.json -Quiet
#>

[CmdletBinding()]
param(
    [switch]$IncludeRdpFiles,
    [switch]$AllUsers,
    [switch]$SkipCredentialCheck,
    [switch]$SkipEventLog,
    [int]$MaxEvents = 500,
    [string]$ExportCsv,
    [string]$ExportJson,
    [switch]$Quiet
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# P/Invoke helper to read a registry key's LastWriteTime - .NET's Microsoft.Win32.RegistryKey
# doesn't expose this directly, so we ask advapi32 for it via the key's handle.
if (-not ('RdpScan.RegistryTime' -as [type])) {
    Add-Type -Namespace RdpScan -Name RegistryTime -MemberDefinition @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
    System.Text.StringBuilder lpClass,
    ref uint lpcchClass,
    IntPtr lpReserved,
    out uint lpcSubKeys,
    out uint lpcbMaxSubKeyLen,
    out uint lpcbMaxClassLen,
    out uint lpcValues,
    out uint lpcbMaxValueNameLen,
    out uint lpcbMaxValueLen,
    out uint lpcbSecurityDescriptor,
    out long lpftLastWriteTime);
'@
}

function Get-RegistryLastWriteTime {
    param([Parameter(Mandatory)][Microsoft.Win32.RegistryKey]$Key)

    try {
        $classLen = 0
        $subKeys = $maxSubKeyLen = $maxClassLen = $values = $maxValueNameLen = 0
        $maxValueLen = $secDescriptor = 0
        $fileTime = 0L

        $rc = [RdpScan.RegistryTime]::RegQueryInfoKey(
            $Key.Handle, $null, [ref]$classLen, [IntPtr]::Zero,
            [ref]$subKeys, [ref]$maxSubKeyLen, [ref]$maxClassLen,
            [ref]$values, [ref]$maxValueNameLen, [ref]$maxValueLen,
            [ref]$secDescriptor, [ref]$fileTime)

        if ($rc -eq 0 -and $fileTime -gt 0) {
            return [DateTime]::FromFileTime($fileTime)
        }
    }
    catch {
        Write-Verbose "Could not read LastWriteTime for $($Key.Name): $($_.Exception.Message)"
    }
    return $null
}

function Get-SavedCredentialMap {
    # Maps lowercased host -> saved cmdkey username, for TERMSRV/<host> targets.
    $map = @{}
    try {
        $output = cmdkey /list 2>$null
    }
    catch {
        Write-Verbose "cmdkey is not available: $($_.Exception.Message)"
        return $map
    }
    if (-not $output) { return $map }

    $currentTarget = $null
    foreach ($line in $output) {
        if ($line -match 'Target:\s*TERMSRV/(.+)$') {
            $currentTarget = $Matches[1].Trim().ToLowerInvariant()
        }
        elseif ($currentTarget -and $line -match 'User:\s*(.+)$') {
            $map[$currentTarget] = $Matches[1].Trim()
            $currentTarget = $null
        }
    }
    return $map
}

function Get-RdpEventLogMap {
    param([int]$MaxEvents = 500)

    # Maps lowercased host -> @{ LastConnectTime; ConnectCount }
    $map = @{}
    $logName = 'Microsoft-Windows-TerminalServices-RDPClient/Operational'

    try {
        $events = Get-WinEvent -LogName $logName -MaxEvents $MaxEvents -ErrorAction Stop |
            Where-Object { $_.Id -eq 1024 -or $_.Id -eq 1102 }
    }
    catch {
        Write-Verbose "RDPClient event log unavailable: $($_.Exception.Message)"
        return $map
    }

    foreach ($event in $events) {
        $target = $null
        try {
            # Event 1024's message is "...trying to connect to the server '<name>'."
            if ($event.Message -match "server '([^']+)'") {
                $target = $Matches[1].Trim().ToLowerInvariant()
            }
        }
        catch { continue }

        if (-not $target) { continue }

        if (-not $map.ContainsKey($target)) {
            $map[$target] = [ordered]@{ LastConnectTime = $event.TimeCreated; ConnectCount = 0 }
        }
        $map[$target].ConnectCount++
        if ($event.TimeCreated -gt $map[$target].LastConnectTime) {
            $map[$target].LastConnectTime = $event.TimeCreated
        }
    }
    return $map
}

function Get-RdpArtifacts {
    # Reads Servers/* and Default MRU entries under a given
    # "...\Terminal Server Client" registry root, tagging each result with $UserLabel.
    param(
        [Parameter(Mandatory)][string]$ClientRoot,
        [Parameter(Mandatory)][string]$UserLabel
    )

    $found = [System.Collections.Generic.List[object]]::new()

    $serversPath = Join-Path $ClientRoot 'Servers'
    $serverKeys = Get-ChildItem -Path $serversPath -ErrorAction SilentlyContinue

    $index = 1
    foreach ($key in $serverKeys) {
        $hostName = $key.PSChildName

        try {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to read properties for '$hostName' ($UserLabel): $($_.Exception.Message)"
            continue
        }

        $entry = [ordered]@{
            Source          = 'ServerHistory'
            User            = $UserLabel
            Index           = $index++
            Host            = $hostName
            UsernameHint    = $null
            LastWriteTime   = Get-RegistryLastWriteTime -Key $key
        }

        foreach ($property in $props.PSObject.Properties) {
            if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }

            if ($property.Name -eq 'UsernameHint') {
                $entry.UsernameHint = $property.Value
            }
            else {
                $entry[$property.Name] = $property.Value
            }
        }

        $found.Add([PSCustomObject]$entry)
    }

    $defaultPath = Join-Path $ClientRoot 'Default'
    try {
        $defaultKey = Get-Item -Path $defaultPath -ErrorAction Stop
        $mruProps = Get-ItemProperty -Path $defaultPath -ErrorAction Stop
        $mruLastWrite = Get-RegistryLastWriteTime -Key $defaultKey

        $mruIndex = 0
        foreach ($property in $mruProps.PSObject.Properties) {
            if ($property.Name -notmatch '^MRU\d+$') { continue }

            $found.Add([PSCustomObject][ordered]@{
                Source        = 'MRU'
                User          = $UserLabel
                Index         = $mruIndex++
                Host          = $property.Value
                UsernameHint  = $null
                LastWriteTime = $mruLastWrite
            })
        }
    }
    catch {
        Write-Verbose "No MRU list found at $defaultPath"
    }

    return $found
}

function Get-RdpFileArtifacts {
    param(
        [Parameter(Mandatory)][string[]]$SearchRoots,
        [Parameter(Mandatory)][string]$UserLabel
    )

    $found = [System.Collections.Generic.List[object]]::new()
    $roots = $SearchRoots | Where-Object { $_ -and (Test-Path $_) }
    if (-not $roots) { return $found }

    $rdpFiles = Get-ChildItem -Path $roots -Filter '*.rdp' -Recurse -ErrorAction SilentlyContinue -File

    foreach ($file in $rdpFiles) {
        $content = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
        $address = ($content | Where-Object { $_ -match '^full address:s:' }) -replace '^full address:s:', ''
        $user    = ($content | Where-Object { $_ -match '^username:s:' }) -replace '^username:s:', ''

        $found.Add([PSCustomObject][ordered]@{
            Source        = 'RdpFile'
            User          = $UserLabel
            Index         = $null
            Host          = "$address".Trim()
            UsernameHint  = "$user".Trim()
            LastWriteTime = $file.LastWriteTime
            Path          = $file.FullName
        })
    }
    return $found
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$results = [System.Collections.Generic.List[object]]::new()
$currentUser = $env:USERNAME

# --- Current user: registry ---
Get-RdpArtifacts -ClientRoot 'HKCU:\Software\Microsoft\Terminal Server Client' -UserLabel $currentUser |
    ForEach-Object { $results.Add($_) }

# --- Current user: saved .rdp files ---
if ($IncludeRdpFiles) {
    $roots = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('MyDocuments'),
        (Join-Path $env:USERPROFILE 'Downloads')
    )
    Get-RdpFileArtifacts -SearchRoots $roots -UserLabel $currentUser |
        ForEach-Object { $results.Add($_) }
}

# --- Other local users (opt-in, needs elevation) ---
if ($AllUsers) {
    if (-not (Test-IsAdmin)) {
        Write-Warning "-AllUsers requires an elevated PowerShell session; skipping other user profiles."
    }
    else {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Special -and $_.LocalPath -and (Split-Path $_.LocalPath -Leaf) -ne $currentUser }

        foreach ($profile in $profiles) {
            $sid = $profile.SID
            $label = Split-Path $profile.LocalPath -Leaf
            $loadedHere = $false
            $hiveRoot = "Registry::HKEY_USERS\$sid"

            try {
                if (-not (Test-Path $hiveRoot)) {
                    $ntUserPath = Join-Path $profile.LocalPath 'NTUSER.DAT'
                    if (-not (Test-Path $ntUserPath)) {
                        Write-Warning "Skipping '$label': NTUSER.DAT not found (profile may be roaming/corrupt)."
                        continue
                    }

                    $loadArgs = @('load', "HKU\$sid", "`"$ntUserPath`"")
                    $proc = Start-Process -FilePath reg.exe -ArgumentList $loadArgs -NoNewWindow -Wait -PassThru -ErrorAction Stop
                    if ($proc.ExitCode -ne 0) {
                        Write-Warning "Skipping '$label': could not load hive (in use or access denied)."
                        continue
                    }
                    $loadedHere = $true
                }

                Get-RdpArtifacts -ClientRoot "$hiveRoot\Software\Microsoft\Terminal Server Client" -UserLabel $label |
                    ForEach-Object { $results.Add($_) }

                if ($IncludeRdpFiles) {
                    $roots = @(
                        (Join-Path $profile.LocalPath 'Desktop'),
                        (Join-Path $profile.LocalPath 'Documents'),
                        (Join-Path $profile.LocalPath 'Downloads')
                    )
                    Get-RdpFileArtifacts -SearchRoots $roots -UserLabel $label |
                        ForEach-Object { $results.Add($_) }
                }
            }
            catch {
                Write-Warning "Skipping '$label': $($_.Exception.Message)"
            }
            finally {
                if ($loadedHere) {
                    [gc]::Collect()
                    [gc]::WaitForPendingFinalizers()
                    Start-Process -FilePath reg.exe -ArgumentList @('unload', "HKU\$sid") -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }
}

# --- Cross-reference: saved credentials (cmdkey) ---
if (-not $SkipCredentialCheck) {
    $credMap = Get-SavedCredentialMap
    foreach ($entry in $results) {
        if (-not $entry.Host) { continue }
        $key = $entry.Host.ToLowerInvariant()
        if ($credMap.ContainsKey($key)) {
            $entry | Add-Member -NotePropertyName HasSavedCredential -NotePropertyValue $true -Force
            $entry | Add-Member -NotePropertyName SavedCredentialUser -NotePropertyValue $credMap[$key] -Force
        }
        else {
            $entry | Add-Member -NotePropertyName HasSavedCredential -NotePropertyValue $false -Force
        }
    }
}

# --- Cross-reference: RDPClient event log ---
if (-not $SkipEventLog) {
    $eventMap = Get-RdpEventLogMap -MaxEvents $MaxEvents
    foreach ($entry in $results) {
        if (-not $entry.Host) { continue }
        $key = $entry.Host.ToLowerInvariant()
        if ($eventMap.ContainsKey($key)) {
            $entry | Add-Member -NotePropertyName LastEventLogConnectTime -NotePropertyValue $eventMap[$key].LastConnectTime -Force
            $entry | Add-Member -NotePropertyName EventLogConnectCount -NotePropertyValue $eventMap[$key].ConnectCount -Force
        }
    }
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

if (-not $Quiet) {
    if ($results.Count -eq 0) {
        Write-Host "No RDP connection history found." -ForegroundColor Yellow
    }
    else {
        $results |
            Select-Object Source, User, Index, Host, UsernameHint, LastWriteTime, HasSavedCredential, LastEventLogConnectTime |
            Format-Table -AutoSize -Wrap
        Write-Host "`nTotal entries: $($results.Count)" -ForegroundColor Cyan
        Write-Host "(Full details, including any extra registry values and .rdp file paths, are in the returned objects / exports.)" -ForegroundColor DarkGray
    }
}

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Exported CSV to $ExportCsv" -ForegroundColor Green
}

if ($ExportJson) {
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $ExportJson -Encoding UTF8
    Write-Host "Exported JSON to $ExportJson" -ForegroundColor Green
}

# Return objects to the pipeline for further processing (e.g. | Where-Object ...)
$results
