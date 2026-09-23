#Requires -Version 5.1
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Turns the CSVs from Invoke-NTFSPermissionAudit.ps1 into an interactive HTML
    "access map" -- a collapsible folder/subfolder tree with identity detail at
    every level -- with no server, no database, and no external JavaScript
    libraries. Open the resulting AccessMap.html directly in a browser.

.DESCRIPTION
    There isn't really a mainstream "BloodHound for filesystem ACLs": BloodHound itself
    maps Active Directory relationships (not NTFS permissions) and needs a Neo4j server
    running; the tools that do map filesystem access (Sysinternals AccessChk/AccessEnum,
    the NTFSSecurity module, commercial products like Varonis/Netwrix) are either
    CLI/text-only or need an agent and a server of their own. This script instead turns
    the CSVs you already have into a portable HTML report, written to -OutputFolder as:

      AccessMap.html          -- the viewer itself: a byte-for-byte copy of
                                  AccessMapTemplate.html, never templated or
                                  rewritten by this script, so it's safe to
                                  edit/diff/version-control directly.
      AccessMap_data/
        manifest.js            -- identities, folders, and every dashboard-level
                                   total, loaded eagerly (small regardless of
                                   audit size -- one entry per identity/folder,
                                   never per access grant).
        share_0.js, share_1.js, ... -- one file per top-level share
                                   (\\server\share), each holding just that
                                   share's access entries (folder x identity
                                   ACE rows -- the part of the dataset that
                                   actually gets huge). AccessMap.html fetches
                                   a share's file the moment something on
                                   screen needs it (a folder in that share is
                                   selected, an identity with access there is
                                   selected, or the relationship graph expands
                                   into it) via a plain <script src> tag --
                                   which works from file:// with no server,
                                   unlike fetch()/XHR -- so the whole folder
                                   still opens by just double-clicking
                                   AccessMap.html, and a multi-gigabyte audit
                                   opens (and its dashboard renders) instantly
                                   instead of parsing everything up front.

    Keep AccessMap.html and AccessMap_data/ together (copy/zip/email the whole
    -OutputFolder) -- the HTML file on its own can't load its data.

      - Left sidebar: search/filter across identities and folders, tabbed.
      - Select a folder: info card (inheritance status) + a collapsible tree rooted at
        that folder, showing its actual subfolder structure (not a relationship graph --
        each subfolder's own children branch from it specifically, never pooled with a
        sibling's) + a full sortable table of every identity with access to it.
      - Select an identity: info card (title/department/manager/enabled/last logon from
        ADIdentityDetails.csv) + the same kind of tree, but with one independent root
        per folder that identity directly accesses + a full sortable table of every
        path they can reach.
      - Quick filters for "broken inheritance" folders and "disabled/dormant" identities,
        since those are usually what a review is actually looking for.

    The tree's depth control (1-5, or Full) sets how many levels of subfolder nesting
    to auto-expand -- 1 shows just the selected folder, 2 adds its direct subfolders,
    3 adds their own subfolders in turn, and so on; anything can also be expanded or
    collapsed manually regardless of the depth setting. Because it's a genuine
    subfolder hierarchy rather than a relationship graph, there's no way for something
    outside a given folder's own contents to appear when browsing it. AccessMap.html
    itself never references the internet and needs no server -- see .DESCRIPTION above
    for how its data is laid out and loaded.

.PARAMETER InputFolder
    The output folder from a previous Invoke-NTFSPermissionAudit.ps1 run. Its CSV
    file names include a run timestamp (e.g. IdentityPermissions_20260910_211500.csv);
    this script finds the matching set of files automatically. If -InputFolder
    contains more than one run's files (you pointed multiple runs at the same
    folder), the most recent set (by file timestamp) is used, with a warning --
    pass a folder containing just the one run you want if that's ambiguous.

.PARAMETER OutputFolder
    Where to write the report -- AccessMap.html plus its AccessMap_data\ subfolder
    (see .DESCRIPTION). Accepts either:
      - An existing, empty directory, or a path that doesn't exist yet (created
        automatically) -- used exactly as given.
      - Omitted entirely -- defaults to a timestamped subfolder of -InputFolder
        (e.g. C:\Audit\Run1\AccessMap_20260910_211500\).
    If you pass an existing, NON-empty directory, this deliberately errors instead
    of mixing generated files into a folder that already has other content --
    point at a different/empty output location (or re-run with -Force to write
    into it anyway).

.PARAMETER Force
    Only needed if -OutputFolder already exists and is non-empty; without it, the
    script errors rather than silently mixing its output into existing content or
    overwriting files there.

.PARAMETER MaxEdgesPerNode
    How many subfolders to show under a single folder in the tree before
    truncating with a "+N more" note (the full list is still always in the
    table when you select that folder directly). Default 60 -- lower it if a
    folder with an unusually large number of direct subfolders makes the tree
    slow or hard to scan.

.EXAMPLE
    .\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -ExpandGroups -OutputFolder C:\Audit\Run1
    .\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1
    # Then just double-click C:\Audit\Run1\AccessMap_<timestamp>\AccessMap.html

.NOTES
    Version: 0.6.3

    Minimum PowerShell 5.1. Requires IdentityPermissions.csv from a prior audit run;
    ADIdentityDetails.csv is optional but strongly recommended (without it, identity
    nodes show only name/type, no department/manager/account-state info).

    Access entries (edges) are partitioned by top-level share and written lazily-
    loaded, so audits with millions of ACE rows still open and render their
    dashboard instantly -- see .DESCRIPTION. The soft warnings below about very
    large inputs are about THIS SCRIPT's own memory use while reading the source
    CSV and building that partition, not about the browser experience of the
    resulting report.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [Alias('OutputHtmlPath')]
    [string]$OutputFolder,

    [int]$MaxEdgesPerNode = 60,

    [switch]$Force
)

$ScriptVersion = '0.6.3'

$ErrorActionPreference = 'Stop'

$InputFolder = (Resolve-Path -LiteralPath $InputFolder).ProviderPath

# Invoke-NTFSPermissionAudit.ps1's output file names include a run timestamp (e.g.
# IdentityPermissions_20260910_211500.csv), so find the matching file(s) by pattern
# rather than assuming a fixed name. A legacy fixed name is still accepted as a
# fallback (e.g. a file that was manually renamed).
function Get-RunTimestampFromName {
    # Extracts the run timestamp embedded in an audit output filename (the
    # yyyyMMdd_HHmmss immediately before the extension). Returns $null for a
    # name that doesn't carry one (e.g. a manually renamed legacy file).
    param([Parameter(Mandatory)][string]$FileName)
    if ($FileName -match '_(\d{8}_\d{6})\.(csv|log)$') { return $Matches[1] }
    return $null
}

function Find-LatestRunFile {
    param([Parameter(Mandatory)][string]$Prefix, [switch]$Required)

    $candidates = @(Get-ChildItem -LiteralPath $InputFolder -Filter "$Prefix*.csv" -File -ErrorAction SilentlyContinue)

    if ($candidates.Count -eq 0) {
        $legacy = Join-Path $InputFolder "$Prefix.csv"
        if (Test-Path -LiteralPath $legacy) { return $legacy }
        if ($Required) { throw "$Prefix*.csv not found in '$InputFolder'. Run Invoke-NTFSPermissionAudit.ps1 first." }
        return $null
    }
    # Sort by the run timestamp EMBEDDED IN THE FILENAME, not filesystem
    # LastWriteTime -- when -InputFolder holds more than one run's output,
    # LastWriteTime can disagree with which run a file actually belongs to
    # (a file copied, restored from backup, or touched later than it was
    # written), which would otherwise risk silently pairing IdentityPermissions
    # from one run with ADIdentityDetails from a completely different one.
    # A file whose name doesn't carry a recognizable timestamp (legacy/manually
    # renamed) falls back to LastWriteTime, since there's nothing more
    # authoritative to sort it by.
    $sorted = $candidates | Sort-Object -Descending -Property @{
        Expression = {
            $ts = Get-RunTimestampFromName $_.Name
            if ($ts) { $ts } else { $_.LastWriteTime.ToString('yyyyMMdd_HHmmss') }
        }
    }
    if ($sorted.Count -gt 1) {
        Write-Warning "Multiple $Prefix*.csv files found in '$InputFolder' (output from more than one audit run?). Using the most recent by run timestamp: $($sorted[0].Name). Point -InputFolder at a folder containing just the run you want if this isn't what you intended."
    }
    return $sorted[0].FullName
}

$identityPermsFile = Find-LatestRunFile -Prefix 'IdentityPermissions' -Required
$identityPermsPath = $identityPermsFile
$adDetailsPath     = Find-LatestRunFile -Prefix 'ADIdentityDetails'
$errorsLogPath     = $null
$errorsLogCandidates = @(Get-ChildItem -LiteralPath $InputFolder -Filter 'Errors_*.log' -File -ErrorAction SilentlyContinue)
if ($errorsLogCandidates.Count -eq 0) {
    $legacyErrorsLog = Join-Path $InputFolder 'Errors.log'
    if (Test-Path -LiteralPath $legacyErrorsLog) { $errorsLogPath = $legacyErrorsLog }
}
else {
    # Same reasoning as Find-LatestRunFile above: sort by the run timestamp
    # embedded in the filename, not filesystem LastWriteTime.
    $errorsSorted = $errorsLogCandidates | Sort-Object -Descending -Property @{
        Expression = {
            $ts = Get-RunTimestampFromName $_.Name
            if ($ts) { $ts } else { $_.LastWriteTime.ToString('yyyyMMdd_HHmmss') }
        }
    }
    if ($errorsSorted.Count -gt 1) {
        Write-Warning "Multiple Errors_*.log files found in '$InputFolder' (output from more than one audit run?). Using the most recent by run timestamp: $($errorsSorted[0].Name)."
    }
    $errorsLogPath = $errorsSorted[0].FullName
}

# Reuse the source run's timestamp for the default output file name too, so the
# HTML file visibly pairs with the CSVs it was built from. Falls back to "now" if
# the chosen file doesn't match the expected timestamp pattern (e.g. it was the
# legacy fixed-name fallback, or was renamed).
$RunTimestamp = if ($identityPermsFile -match '_(\d{8}_\d{6})\.csv$') { $Matches[1] } else { Get-Date -Format 'yyyyMMdd_HHmmss' }

# A run that was interrupted (killed, crashed, machine rebooted) before
# finishing never gets to write Completed_<timestamp>.marker -- its absence is
# how -Resume itself knows there's something to continue, and it's exactly as
# useful a signal here: if it's missing, the CSVs this HTML is built from are
# real and not corrupt, just incomplete (some part of the tree was never
# reached). Only checked when the run's own timestamp was actually
# identifiable above; a legacy/renamed file has no timestamp to look up a
# marker for, so completeness simply can't be determined for it either way.
$scanComplete = $true
if ($identityPermsFile -match '_(\d{8}_\d{6})\.csv$') {
    $completedMarkerPath = Join-Path $InputFolder "Completed_$RunTimestamp.marker"
    $scanComplete = Test-Path -LiteralPath $completedMarkerPath
    if (-not $scanComplete) {
        Write-Warning "No Completed_$RunTimestamp.marker found -- this run appears to have been interrupted before finishing. The report will say so and show everything that WAS captured."
    }
}

# Resolve -OutputFolder into a concrete target directory:
#   - omitted -> a timestamped subfolder of -InputFolder
#   - doesn't exist yet -> created
#   - exists and is empty -> used as-is
#   - exists and is NON-empty -> error unless -Force (deliberately -- don't mix
#     this run's AccessMap.html/AccessMap_data into a folder that already has
#     other content, most commonly a previous run's own output)
if (-not $OutputFolder) {
    $OutputFolder = Join-Path $InputFolder "AccessMap_$RunTimestamp"
}
if (Test-Path -LiteralPath $OutputFolder) {
    if ((Get-Item -LiteralPath $OutputFolder) -isnot [System.IO.DirectoryInfo]) {
        throw "'$OutputFolder' already exists and is a file, not a folder. -OutputFolder must be a directory -- this script writes AccessMap.html plus an AccessMap_data subfolder into it, not a single file."
    }
    $existingItems = @(Get-ChildItem -LiteralPath $OutputFolder -Force -ErrorAction SilentlyContinue)
    if ($existingItems.Count -gt 0 -and -not $Force) {
        throw "'$OutputFolder' is an existing, non-empty folder. Re-run with -Force to write into it anyway (existing AccessMap.html/AccessMap_data from a previous run will be overwritten), or point -OutputFolder at a different/empty location."
    }
}
else {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath
$OutputHtmlPath = Join-Path $OutputFolder 'AccessMap.html'
$DataDirName = 'AccessMap_data'
$DataDirPath = Join-Path $OutputFolder $DataDirName
New-Item -ItemType Directory -Path $DataDirPath -Force | Out-Null

Write-Host "Build-AccessMapHtml v$ScriptVersion" -ForegroundColor Cyan

# A process killed mid-write can leave a CSV's LAST line truncated -- cut off
# anywhere in it, not necessarily in a way that nulls out a specific field
# (confirmed directly: chopping through the middle of a quoted field's TEXT
# just silently shortens that one value, e.g. "This folder, subfolders and
# files" becomes "This folder, sub" -- Import-Csv has no way to know that
# wasn't the real value). The robust, general signal isn't "is some field
# null" but simply: does the raw file end with a newline at all? A properly
# completed row always does (checked directly against real Export-Csv output
# on this platform, which turned out to use bare LF rather than CRLF --
# checking only for the trailing LF byte, not CRLF specifically, is what
# makes this portable across that difference); a row cut off mid-write by a
# killed process essentially never does, regardless of which field or how
# much of it got cut.
$script:truncatedRowsDropped = 0
Add-Type -AssemblyName Microsoft.VisualBasic

function Import-CsvRobust {
    <#
        Streams rows one at a time via TextFieldParser instead of loading the
        whole file into memory as an array of PSCustomObjects the way
        Import-Csv does -- a real, structural difference on a very large
        file, not just a theoretical one, since Import-Csv must hold every
        row simultaneously by design (confirmed directly: its own array
        alone is the first thing to exhaust memory on a large file, before
        this script's own edges/identities/folders accumulation even gets a
        turn). TextFieldParser is a robust, quote-aware CSV parser built into
        .NET (correctly handles embedded commas/quotes in a field, verified
        directly, not just assumed) -- not a hand-rolled comma-split.

        Still detects and drops a truncated last row (from a process killed
        mid-write) using the same "does the raw file end with a newline"
        check as before, computed once up front via a separate, cheap
        byte-level check (unaffected by file size). A one-row lookahead
        buffer inside the streaming loop withholds the very last row until
        we know whether to actually emit it, without ever needing to hold
        more than one row in memory at a time to make that call.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $endsWithNewline = $false
    $fs = [System.IO.File]::OpenRead($Path)
    try {
        if ($fs.Length -gt 0) {
            $fs.Seek(-1, [System.IO.SeekOrigin]::End) | Out-Null
            $endsWithNewline = ($fs.ReadByte() -eq 10)   # LF; also the last byte of a CRLF ending
        }
    }
    finally { $fs.Dispose() }

    $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($Path)
    $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
    $parser.SetDelimiters(',')
    $parser.HasFieldsEnclosedInQuotes = $true
    try {
        if ($parser.EndOfData) { return }
        $headers = $parser.ReadFields()

        $pending = $null
        $hitMalformedLine = $false
        while (-not $parser.EndOfData) {
            try {
                $fields = $parser.ReadFields()
            }
            catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
                # TextFieldParser is stricter than Import-Csv here (confirmed
                # directly, not assumed): a truncated/malformed line -- e.g. an
                # unterminated quote from a process killed mid-write -- makes
                # Import-Csv silently return a partial/null-padded row, but
                # makes TextFieldParser throw outright. Treated the same way
                # either way: this is the truncated row, drop it, stop
                # reading (the file's structure past this point can't be
                # trusted), but still emit whatever was successfully read and
                # held back as $pending before this happened.
                $hitMalformedLine = $true
                break
            }
            $obj = [ordered]@{}
            for ($h = 0; $h -lt $headers.Count; $h++) {
                $obj[$headers[$h]] = if ($h -lt $fields.Count) { $fields[$h] } else { $null }
            }
            if ($null -ne $pending) { Write-Output $pending }
            $pending = [PSCustomObject]$obj
        }
        if ($null -ne $pending) {
            if ($hitMalformedLine) {
                # $pending is a genuinely complete row (it parsed fine); the
                # malformed content came AFTER it and was never captured as a
                # row at all, so $pending itself is safe to keep.
                Write-Output $pending
                Write-Warning "'$Path' has a malformed line near the end (consistent with a process killed mid-write) -- the incomplete trailing content was dropped; everything successfully parsed, including the row just before it, is kept."
                $script:truncatedRowsDropped++
            }
            elseif ($endsWithNewline) {
                Write-Output $pending
            }
            else {
                Write-Warning "'$Path' doesn't end with a newline -- looks like the file was truncated mid-write (a killed/crashed run). Dropping that one incomplete last row; everything else in the file is unaffected."
                $script:truncatedRowsDropped++
            }
        }
    }
    finally { $parser.Dispose() }
}

# A very large source file is the scenario the streaming reader above exists
# for -- warn early and clearly rather than let someone wait through a long,
# memory-heavy run only to have it fail uninformatively partway through. This
# is a soft warning, not a hard block: the streaming reader itself has no
# fixed ceiling, but this SCRIPT still accumulates identities/folders/edges
# in memory as it goes (the final output is partitioned by share and written
# incrementally -- see "Serialize and emit" below -- so the OUTPUT no longer
# has to fit in memory or in a browser as one piece; this warning is only
# about Build-AccessMapHtml.ps1's own working set while it reads the CSV).
$identityPermsSizeMB = (Get-Item -LiteralPath $identityPermsPath).Length / 1MB
if ($identityPermsSizeMB -gt 300) {
    Write-Warning "$identityPermsPath is $([math]::Round($identityPermsSizeMB)) MB. This script still holds every identity/folder/access-entry in memory while it reads the CSV (the .NET object overhead per row is larger than the row's own text), so a very large input can still be slow or memory-heavy to BUILD even though the resulting report now loads its data lazily per share and stays fast to OPEN. If building it here runs into trouble, the fix is the same as ever -- scan and build one share/subtree at a time (re-run Invoke-NTFSPermissionAudit.ps1 with -Path pointed at each major share separately) and build a map per share on a machine with more memory, rather than one combined report for an entire file server in one pass."
}

Write-Host "Reading $identityPermsPath ..." -ForegroundColor Cyan

$adDetails = @{}
if ($adDetailsPath -and (Test-Path -LiteralPath $adDetailsPath)) {
    Write-Host "Reading $adDetailsPath ..." -ForegroundColor Cyan
    foreach ($row in (Import-CsvRobust -Path $adDetailsPath)) {
        if ($row.IdentitySid) { $adDetails[$row.IdentitySid] = $row }
    }
    Write-Verbose "Loaded AD details for $($adDetails.Count) identity(ies)."
}
else {
    Write-Warning "No ADIdentityDetails*.csv found in '$InputFolder'. Identity nodes will show name/type only (no department/manager/account-state info)."
}

# Errors.log records objects the audit couldn't read an ACL for at all (access
# denied, path too long, etc.) -- these are folders that simply don't appear
# anywhere in IdentityPermissions.csv, so without this they'd be silently
# invisible to anyone looking at the access map. Parsed into the summary view
# as "folders that could not be scanned" rather than left as a text log only.
$scanErrors = New-Object System.Collections.Generic.List[object]
if ($errorsLogPath -and (Test-Path -LiteralPath $errorsLogPath)) {
    Write-Host "Reading $errorsLogPath ..." -ForegroundColor Cyan
    $errorLinePattern = '^\[(?<ts>[^\]]+)\]\s(?<path>.+?)\s::\s(?<msg>.+)$'
    # A -Resume run's Errors.log can legitimately contain TWO entries for the
    # same path: one from before the crash (an item that was processed but
    # not yet checkpointed when the process died) and one from after resuming
    # (that same item, correctly redone). Both are real log entries and both
    # stay in the raw log file, but for THIS report -- which is meant to
    # answer "how many distinct objects couldn't be scanned" -- counting that
    # one folder twice would overstate the problem. Deduplicated by path,
    # keeping the most recent attempt (in the same order the log itself was
    # written), immediately after parsing.
    $rawErrors = New-Object System.Collections.Generic.List[object]
    foreach ($line in (Get-Content -LiteralPath $errorsLogPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $m = [regex]::Match($line, $errorLinePattern)
        if ($m.Success) {
            $msg = $m.Groups['msg'].Value
            $category = switch -Regex ($msg) {
                'Access denied'                      { 'Access denied'; break }
                'PathTooLong|too long|not supported.*platform' { 'Path/platform limitation'; break }
                default                               { 'Other' }
            }
            $rawErrors.Add([PSCustomObject]@{
                Timestamp = $m.Groups['ts'].Value
                Path      = $m.Groups['path'].Value
                Message   = $msg
                Category  = $category
            })
        }
        else {
            # Line didn't match the usual "[ts] path :: message" shape (e.g. a
            # wrapped/multi-line message) -- keep it rather than silently drop it.
            # No meaningful Path to dedupe by, so always kept as its own entry.
            $rawErrors.Add([PSCustomObject]@{ Timestamp = $null; Path = $null; Message = $line; Category = 'Other' })
        }
    }
    $seenPaths = @{}
    $dedupedCount = 0
    foreach ($err in $rawErrors) {
        if ($null -eq $err.Path) { $scanErrors.Add($err); continue }
        if ($seenPaths.ContainsKey($err.Path)) {
            # A later entry for a path already seen: replace the earlier one
            # (it's the more recent attempt) rather than adding a duplicate.
            $scanErrors[$seenPaths[$err.Path]] = $err
            $dedupedCount++
        }
        else {
            $scanErrors.Add($err)
            $seenPaths[$err.Path] = $scanErrors.Count - 1
        }
    }
    if ($dedupedCount -gt 0) {
        Write-Host "$dedupedCount duplicate error entry/entries (same path logged more than once -- consistent with a -Resume run redoing an interrupted item) were collapsed to the most recent attempt." -ForegroundColor Cyan
    }
    Write-Verbose "Loaded $($scanErrors.Count) distinct scan error(s) (from $($rawErrors.Count) raw log line(s))."
}
else {
    Write-Verbose "No Errors*.log found in '$InputFolder' -- assuming a clean scan with nothing to report."
}

#region Build compact index structures -----------------------------------------

# Rights are encoded as a small integer to keep the emitted JS compact; the
# HTML/JS template's RIGHTS_LABELS array (kept in the same order) turns these
# back into text for display.
$rightsCodeMap = @{
    'Full Control'   = 0
    'Modify'         = 1
    'Read & Execute' = 2
    'Read'           = 3
    'Write'          = 4
    'Special'        = 5
}
function Get-RightsCode {
    param([string]$Summary)
    if ($rightsCodeMap.ContainsKey($Summary)) { return $rightsCodeMap[$Summary] }
    return 5   # unrecognised -> treat as "Special" bucket rather than losing the row
}
function ConvertTo-Bool {
    param([string]$Text)
    return ($Text -eq 'True' -or $Text -eq 'true' -or $Text -eq '1')
}

# Some rows can carry a Windows extended-length path prefix (\\?\UNC\ for a
# network path, \\?\ for a local drive path) instead of the normal form --
# .NET's own long-path handling can independently decide to hand back a
# prefixed child path based on the CHILD's own resulting length, even when
# its parent's path was short enough not to need one (a real bug in
# Invoke-NTFSPermissionAudit.ps1's own un-prefixing logic, fixed there too,
# but existing CSVs captured before that fix still have it baked in and
# can't be re-scanned just to pick up the fix). Left alone, this breaks
# EVERYTHING that depends on paths being in one consistent form: two spans
# of the very same folder tree end up looking like different addressing
# schemes, so a deep folder's computed parent path no longer string-matches
# its own ancestor (fracturing the tree exactly at the depth where the
# prefix kicks in) and its share key comes out as "\\?\UNC" for every prefixed
# folder regardless of which real share it's actually in (collapsing what
# should be several independently-loadable shares into one). Normalizing
# every path to the same plain form, once, here, fixes both at the root.
function Get-NormalizedPath {
    param([string]$Path)
    if ($Path.StartsWith('\\?\UNC\')) { return '\\' + $Path.Substring(8) }
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

# A folder's "share" is its first two path segments (\\server\share) -- the
# same convention AccessMapTemplate.html's own buildFolderTree() uses to find
# share roots. This is what access entries get partitioned by: everything
# under one share becomes one AccessMap_data\share_N.js file, lazy-loaded by
# the browser only when something in that share is actually opened.
function Get-ShareKeyFromPath {
    param([Parameter(Mandatory)][string]$Path)
    $segs = $Path.Split('\') | Where-Object { $_ -ne '' }
    if ($segs.Count -lt 2) { return $Path }   # shouldn't normally happen; falls back to the whole path as its own "share"
    # Only prepend the UNC "\\" when the path itself actually had one -- for
    # a locally-rooted audit (a plain C:\... path, no UNC prefix at all),
    # unconditionally prepending it fabricated a share key ("\\D:\Shares")
    # that could never match any of that path's own real ancestors, which
    # broke AccessMapTemplate.html's client-side tree/breadcrumb logic for
    # any dataset scanned from a local path rather than a UNC one.
    $prefix = if ($Path.StartsWith('\\')) { '\\' } else { '' }
    return $prefix + ($segs[0..1] -join '\')
}

# Broad, default principals whose Full Control / Modify grants get flagged in
# the dashboard's "Observations" section (see .broadPrincipalGrants below) --
# same set AccessMapTemplate.html used to filter for client-side; moved here
# so the dashboard never needs a single access entry loaded to show this.
$broadPrincipalNames = New-Object System.Collections.Generic.HashSet[string]
@('everyone', 'authenticated users', 'domain users', 'users') | ForEach-Object { [void]$broadPrincipalNames.Add($_) }

$identityIndex   = New-Object System.Collections.Generic.List[object]   # exported array
$identityLookup  = @{}   # sid -> array index
$identityNameLookup = @{}   # name (lowercase) -> array index, for resolving GrantedViaGroup

function Get-OrAdd-Identity {
    param([string]$Sid, [string]$Name, [string]$Type)

    $key = if ($Sid) { $Sid } else { "name:$Name" }
    if ($identityLookup.ContainsKey($key)) { return $identityLookup[$key] }

    $detail = if ($Sid -and $adDetails.ContainsKey($Sid)) { $adDetails[$Sid] } else { $null }

    $entry = [ordered]@{
        sid       = $Sid
        name      = $Name
        type      = $Type
        title     = if ($detail) { $detail.Title } else { $null }
        dept      = if ($detail) { $detail.Department } else { $null }
        manager   = if ($detail) { $detail.Manager } else { $null }
        email     = if ($detail) { $detail.EmailAddress } else { $null }
        enabled   = if ($detail -and $detail.Enabled) { ConvertTo-Bool $detail.Enabled } else { $null }
        locked    = if ($detail -and $detail.LockedOut) { ConvertTo-Bool $detail.LockedOut } else { $null }
        lastLogon = if ($detail) { $detail.LastLogonTimestampApprox } else { $null }
        pwdSet    = if ($detail) { $detail.PasswordLastSet } else { $null }
        expires   = if ($detail) { $detail.AccountExpirationDate } else { $null }
        created   = if ($detail) { $detail.WhenCreated } else { $null }
        changed   = if ($detail) { $detail.WhenChanged } else { $null }
        groupScope    = if ($detail) { $detail.GroupScope } else { $null }
        memberCount   = if ($detail) { $detail.DirectMemberCount } else { $null }
        managedBy     = if ($detail) { $detail.ManagedBy } else { $null }
        notes     = if ($detail) { $detail.LookupNotes } else { $null }
        # Populated while the main edge loop runs, below -- edgeCount/shareKeys
        # so the client can know an identity's total reach and which
        # AccessMap_data\share_N.js file(s) to lazy-load for it WITHOUT ever
        # needing every share loaded just to answer "does this identity have
        # any access, and where"; members so the relationship graph's "who
        # else is in this group" traversal is global/eager and never needs to
        # lazy-load every share a hub group happens to grant access in.
        edgeCount = 0
        shareKeys = (New-Object System.Collections.Generic.HashSet[string])
    }
    $identityIndex.Add($entry)
    $idx = $identityIndex.Count - 1
    $identityLookup[$key] = $idx
    if ($Name) { $identityNameLookup[$Name.ToLowerInvariant()] = $idx }
    return $idx
}

# Seed the identity index from ADIdentityDetails.csv first, so every known
# identity (including ones that only show up as a GrantedViaGroup reference)
# gets a full entry even if a later loop encounters it first by name only.
foreach ($sid in ($adDetails.Keys | Sort-Object)) {
    $d = $adDetails[$sid]
    Get-OrAdd-Identity -Sid $sid -Name $d.IdentityName -Type $d.IdentityType | Out-Null
}

$folderIndex  = New-Object System.Collections.Generic.List[object]
$folderLookup = @{}   # path -> array index
$shareOrder   = New-Object System.Collections.Generic.List[string]   # share keys, first-seen order
$shareFolderCounts = @{}   # share key -> distinct folder count

function Get-OrAdd-Folder {
    param([string]$Path)
    if ($folderLookup.ContainsKey($Path)) { return $folderLookup[$Path] }
    $shareKey = Get-ShareKeyFromPath -Path $Path
    if (-not $shareFolderCounts.ContainsKey($shareKey)) {
        $shareFolderCounts[$shareKey] = 0
        [void]$shareOrder.Add($shareKey)
    }
    $shareFolderCounts[$shareKey]++
    # broken is set to $true in-place, below, the moment the edge loop sees an
    # InheritanceBrokenHere=True row for this folder -- precomputed here
    # rather than left for the client to derive from edges (which, once
    # partitioned by share, wouldn't all be loaded at once to derive it from).
    $folderIndex.Add([ordered]@{ path = $Path; broken = $false; share = $shareKey })
    $idx = $folderIndex.Count - 1
    $folderLookup[$Path] = $idx
    return $idx
}

$edgesByShare = @{}   # share key -> List[object] of 7-element edge tuples (see below)
$brokenInheritanceFolders = New-Object System.Collections.Generic.HashSet[int]
$groupMembers = @{}   # groupIdx -> HashSet[int] of memberIdx (who lists this identity as GrantedViaGroup)
$rightsDistribution = New-Object 'int[]' 6
$broadPrincipalFolders = New-Object System.Collections.Generic.HashSet[int]
$totalEdgeCount = 0
$fileRowsExcluded = 0

$i = 0
foreach ($row in (Import-CsvRobust -Path $identityPermsPath)) {
    $i++
    if ($i % 5000 -eq 0) { Write-Progress -Activity 'Building access map' -Status "$i rows processed" }

    # The interactive map is folder-centric by design (folders are the thing
    # you navigate; identities are the other node type) -- a FILE row's own
    # Path is the file's full path, not a folder, so feeding it through
    # Get-OrAdd-Folder the same way would create a phantom "folder" node for
    # every individual file, silently inflating the folder count (confirmed
    # directly: a folder with 2 files under -IncludeFiles reported 3
    # "folders", not 1). File-level ACE rows remain fully present in the raw
    # IdentityPermissions.csv -- exactly what -IncludeFiles is for, catching
    # file-level exceptions to a folder's own permissions -- just not
    # represented as their own nodes in this interactive map.
    if ($row.ObjectType -eq 'File') { $fileRowsExcluded++; continue }

    $identityIdx = Get-OrAdd-Identity -Sid $row.IdentitySid -Name $row.IdentityName -Type $row.IdentityType
    $folderIdx   = Get-OrAdd-Folder -Path (Get-NormalizedPath $row.Path)
    $shareKey    = $folderIndex[$folderIdx].share

    $inheritanceBroken = ConvertTo-Bool $row.InheritanceBrokenHere
    if ($inheritanceBroken -and -not $folderIndex[$folderIdx].broken) {
        $folderIndex[$folderIdx].broken = $true
        [void]$brokenInheritanceFolders.Add($folderIdx)
    }

    $viaIdx = -1
    if ($row.GrantedViaGroup) {
        $viaKey = $row.GrantedViaGroup.ToLowerInvariant()
        if ($identityNameLookup.ContainsKey($viaKey)) { $viaIdx = $identityNameLookup[$viaKey] }
    }
    if ($viaIdx -ge 0) {
        if (-not $groupMembers.ContainsKey($viaIdx)) { $groupMembers[$viaIdx] = New-Object System.Collections.Generic.HashSet[int] }
        [void]$groupMembers[$viaIdx].Add($identityIdx)
    }

    $rightsCode = Get-RightsCode $row.RightsSummary
    $isDeny     = ConvertTo-Bool ($row.AccessControlType -eq 'Deny')

    if (-not $edgesByShare.ContainsKey($shareKey)) { $edgesByShare[$shareKey] = New-Object System.Collections.Generic.List[object] }
    $edgesByShare[$shareKey].Add(@(
        $folderIdx,
        $identityIdx,
        $rightsCode,
        [int](ConvertTo-Bool $row.IsInheritedAce),
        [int]$inheritanceBroken,
        [int]$isDeny,
        $viaIdx
    ))
    $totalEdgeCount++
    $rightsDistribution[$rightsCode]++

    $identityIndex[$identityIdx].edgeCount++
    [void]$identityIndex[$identityIdx].shareKeys.Add($shareKey)

    # Dashboard "Observations" flag: a broad, default principal (Everyone,
    # Authenticated Users, Domain Users, Users) holding Full Control(0) or
    # Modify(1), not a Deny entry. Precomputed here (once, during the same
    # pass) instead of left for the client to derive by scanning every edge,
    # which -- once edges are partitioned per share -- wouldn't all be loaded
    # at once to derive it from anyway.
    if (-not $isDeny -and ($rightsCode -eq 0 -or $rightsCode -eq 1)) {
        $shortName = ($row.IdentityName -split '\\')[-1]
        if ($shortName -and $broadPrincipalNames.Contains($shortName.ToLowerInvariant())) {
            [void]$broadPrincipalFolders.Add($folderIdx)
        }
    }
}
Write-Progress -Activity 'Building access map' -Completed

Write-Host "Read $i permission row(s).   Identities: $($identityIndex.Count)   Folders: $($folderIndex.Count)   Shares: $($shareOrder.Count)   Edges: $totalEdgeCount   Broken-inheritance folders: $($brokenInheritanceFolders.Count)" -ForegroundColor Green
if ($fileRowsExcluded -gt 0) {
    Write-Host "$fileRowsExcluded file-level access row(s) from -IncludeFiles were excluded from this interactive map (folders/identities only) -- they're still in $identityPermsPath itself." -ForegroundColor Cyan
}
$maxShareEdges = 0
foreach ($k in $edgesByShare.Keys) { if ($edgesByShare[$k].Count -gt $maxShareEdges) { $maxShareEdges = $edgesByShare[$k].Count } }
if ($maxShareEdges -gt 150000) {
    Write-Warning "At least one share has a large number of access entries ($maxShareEdges). That share's own AccessMap_data\share_N.js file may take a moment to fetch and the browser may feel sluggish once you open something in it, even though the rest of the report (dashboard, every other share) stays fast. If that share is itself the problem, re-scan just that subtree on its own (Invoke-NTFSPermissionAudit.ps1 -Path pointed at it directly) and build a separate, smaller map for it."
}

#endregion Build compact index structures ---------------------------------------

#region Serialize and emit -------------------------------------------------------

# identities[].shareKeys was accumulated as a HashSet[string] per identity
# (see Get-OrAdd-Identity) to dedupe cheaply as rows streamed by; ConvertTo-Json
# serializes it as a JSON array fine, but it's converted to a plain array here
# anyway so identityIndex is plain, JSON-ready data with nothing PowerShell-
# specific left in it. Likewise fold in each identity's members (the inverse
# of GrantedViaGroup, built into $groupMembers above) as a plain int array.
for ($gi = 0; $gi -lt $identityIndex.Count; $gi++) {
    $identityIndex[$gi].shareKeys = @($identityIndex[$gi].shareKeys)
    if ($groupMembers.ContainsKey($gi)) {
        $identityIndex[$gi]['members'] = @($groupMembers[$gi])
    }
}

$shareManifest = New-Object System.Collections.Generic.List[object]
for ($si = 0; $si -lt $shareOrder.Count; $si++) {
    $shareKey = $shareOrder[$si]
    $edgeCountForShare = if ($edgesByShare.ContainsKey($shareKey)) { $edgesByShare[$shareKey].Count } else { 0 }
    $shareManifest.Add([ordered]@{
        key         = $shareKey
        label       = $shareKey
        file        = "share_$si.js"
        folderCount = $shareFolderCounts[$shareKey]
        edgeCount   = $edgeCountForShare
    })
}

$manifestObject = [ordered]@{
    identities = $identityIndex
    folders    = $folderIndex
    shares     = $shareManifest
    totalEdgeCount = $totalEdgeCount
    rightsDistribution = $rightsDistribution
    broadPrincipalGrants = [ordered]@{
        folderCount = $broadPrincipalFolders.Count
        folderIdxs  = @($broadPrincipalFolders)
    }
    maxEdgesPerNode = $MaxEdgesPerNode
    generatedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    sourceFolder = $InputFolder
    toolkitVersion = $ScriptVersion
    scanErrors = $scanErrors
    scanComplete = $scanComplete
    truncatedRowsDropped = $script:truncatedRowsDropped
}

Write-Verbose "Writing $DataDirName\manifest.js ..."
$manifestJson = $manifestObject | ConvertTo-Json -Depth 6 -Compress
Set-Content -LiteralPath (Join-Path $DataDirPath 'manifest.js') -Value "const ACCESS_MAP_MANIFEST = $manifestJson;" -Encoding UTF8 -NoNewline

function Write-ShareChunkFile {
    # Edge rows are plain numeric 7-tuples (see the edge loop above) -- no
    # strings, no escaping needed -- so this is written directly as text
    # instead of through ConvertTo-Json. For a collection this size (this is
    # where the bulk of a large audit's data actually lives), that's both far
    # faster than ConvertTo-Json's reflection-based serializer and sidesteps
    # its well-known quirk of collapsing a single-element top-level array
    # down to a bare scalar (a real case here: a share can easily have
    # exactly one access entry).
    param(
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$EdgeRows,
        [Parameter(Mandatory)][string]$ShareKey,
        [Parameter(Mandatory)][string]$Path
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('registerShareChunk(')
    [void]$sb.Append(($ShareKey | ConvertTo-Json -Compress))   # a single string -- not subject to the array-collapse quirk
    [void]$sb.Append(',[')
    $first = $true
    foreach ($e in $EdgeRows) {
        if (-not $first) { [void]$sb.Append(',') }
        $first = $false
        [void]$sb.Append('[')
        [void]$sb.Append([string]::Join(',', $e))
        [void]$sb.Append(']')
    }
    [void]$sb.Append(']);')
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 -NoNewline
}

for ($si = 0; $si -lt $shareOrder.Count; $si++) {
    $shareKey = $shareOrder[$si]
    # NOTE: deliberately NOT "$rows = if (...) { $edgesByShare[$shareKey] } else {...}" --
    # that form pipes the List through PowerShell's success-output stream to produce
    # the if-expression's value, which enumerates it; a List with exactly one element
    # (a real case here -- a share with exactly one access entry) then collapses to
    # that bare element instead of staying a 1-item List. Confirmed live with pwsh
    # before landing this fix. Plain assignment inside each branch sidesteps the
    # pipeline entirely, so no enumeration happens regardless of Count.
    if ($edgesByShare.ContainsKey($shareKey)) {
        $rows = $edgesByShare[$shareKey]
    }
    else {
        $rows = New-Object System.Collections.Generic.List[object]
    }
    $chunkPath = Join-Path $DataDirPath "share_$si.js"
    Write-Verbose "Writing $DataDirName\share_$si.js ($($rows.Count) edge(s) for $shareKey) ..."
    Write-ShareChunkFile -EdgeRows $rows -ShareKey $shareKey -Path $chunkPath
}

$templatePath = Join-Path $PSScriptRoot 'AccessMapTemplate.html'
if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "Template file not found: $templatePath (expected alongside this script)."
}
# AccessMapTemplate.html is never templated or rewritten -- it's copied
# byte-for-byte as AccessMap.html and loads its data at runtime from the
# AccessMap_data\ files just written above (see the .DESCRIPTION at the top
# of this script). That's what makes the viewer itself safe to edit, diff,
# and version-control directly, independent of any one run's data.
Copy-Item -LiteralPath $templatePath -Destination $OutputHtmlPath -Force

Write-Host "Access map written to $OutputHtmlPath" -ForegroundColor Green
Write-Host "($DataDirName\ holds its data -- keep the two together; copy/zip/email the whole '$OutputFolder' folder.)" -ForegroundColor Yellow
Write-Host "Open AccessMap.html directly in a browser -- no server required." -ForegroundColor Yellow

#endregion Serialize and emit -----------------------------------------------------
