#Requires -Version 5.1
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Turns the CSVs from Invoke-NTFSPermissionAudit.ps1 into a single, self-contained,
    interactive HTML "access map" -- a BloodHound-style click-a-node-see-its-neighbors
    view of who has access to what -- with no server, no database, and no external
    JavaScript libraries. Open the resulting .html file directly in a browser.

.DESCRIPTION
    There isn't really a mainstream "BloodHound for filesystem ACLs": BloodHound itself
    maps Active Directory relationships (not NTFS permissions) and needs a Neo4j server
    running; the tools that do map filesystem access (Sysinternals AccessChk/AccessEnum,
    the NTFSSecurity module, commercial products like Varonis/Netwrix) are either
    CLI/text-only or need an agent and a server of their own. This script instead turns
    the CSVs you already have into a single portable HTML file:

      - Left sidebar: search/filter across identities and folders, tabbed.
      - Select an identity: info card (title/department/manager/enabled/last logon from
        ADIdentityDetails.csv) + a radial "ego network" graph of the folders they can
        reach + a full sortable table of every path (with rights/inherited/broken-here/
        granted-via-group), exportable back to CSV from the browser itself.
      - Select a folder: info card (inheritance status) + a radial graph of who has
        access + a full sortable table of every identity, same export option.
      - Quick filters for "broken inheritance" folders and "disabled/dormant" identities,
        since those are usually what a review is actually looking for.

    The radial graph is capped to a manageable number of the most notable edges per
    node (explicit before inherited, higher rights first) to stay readable and fast
    without a query engine behind it -- the full, uncapped list is always in the table
    underneath. All data is embedded directly in the HTML as JSON (not loaded via
    separate files), so it opens correctly straight from disk (file://) with no web
    server and no internet access required, and no external script/CSS files are
    referenced -- everything needed is in the one .html file.

.PARAMETER InputFolder
    The output folder from a previous Invoke-NTFSPermissionAudit.ps1 run. Its CSV
    file names include a run timestamp (e.g. IdentityPermissions_20260910_211500.csv);
    this script finds the matching set of files automatically. If -InputFolder
    contains more than one run's files (you pointed multiple runs at the same
    folder), the most recent set (by file timestamp) is used, with a warning --
    pass a folder containing just the one run you want if that's ambiguous.

.PARAMETER OutputHtmlPath
    Where to write the HTML file. Accepts either:
      - A full path ending in a file name (e.g. C:\Reports\FinanceMap.html) --
        used exactly as given; its parent folder is created if needed.
      - An existing, empty directory -- a timestamped file name is generated
        inside it (matching the source run's timestamp where possible).
      - Omitted entirely -- defaults to a timestamped file name inside
        -InputFolder.
    If you pass an existing directory that is NOT empty, this deliberately
    errors instead of guessing a file name into a folder that already has
    content -- be explicit about the file name in that case (or point at a
    different, empty output directory).

.PARAMETER Force
    Only needed if the resolved output file already exists (most commonly
    because you specified an exact -OutputHtmlPath that collides with a
    previous file); without it, the script errors rather than silently
    overwriting.

.PARAMETER MaxEdgesPerNode
    How many neighbors to draw in the radial graph for a single selected node before
    truncating (the full list is still always in the table below the graph). Default
    60 -- higher values make busy nodes (e.g. "Everyone", or a folder with hundreds of
    ACEs) slower and harder to read.

.EXAMPLE
    .\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -ExpandGroups -OutputFolder C:\Audit\Run1
    .\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1
    # Then just double-click C:\Audit\Run1\AccessMap.html

.NOTES
    Version: 0.1.0

    Minimum PowerShell 5.1. Requires IdentityPermissions.csv from a prior audit run;
    ADIdentityDetails.csv is optional but strongly recommended (without it, identity
    nodes show only name/type, no department/manager/account-state info).

    For very large audits (hundreds of thousands of ACE rows), the resulting HTML file
    embeds every row as JSON and can get large (tens of MB) -- still workable in a
    modern browser, but if it feels sluggish, generate a map per subtree/share instead
    of one for the entire server.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFolder,

    [string]$OutputHtmlPath,

    [int]$MaxEdgesPerNode = 60,

    [switch]$Force
)

$ScriptVersion = '0.1.0'

$ErrorActionPreference = 'Stop'

$InputFolder = (Resolve-Path -LiteralPath $InputFolder).ProviderPath

# Invoke-NTFSPermissionAudit.ps1's output file names include a run timestamp (e.g.
# IdentityPermissions_20260910_211500.csv), so find the matching file(s) by pattern
# rather than assuming a fixed name. A legacy fixed name is still accepted as a
# fallback (e.g. a file that was manually renamed).
function Find-LatestRunFile {
    param([Parameter(Mandatory)][string]$Prefix, [switch]$Required)

    $candidates = @(Get-ChildItem -LiteralPath $InputFolder -Filter "$Prefix*.csv" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    if ($candidates.Count -eq 0) {
        $legacy = Join-Path $InputFolder "$Prefix.csv"
        if (Test-Path -LiteralPath $legacy) { return $legacy }
        if ($Required) { throw "$Prefix*.csv not found in '$InputFolder'. Run Invoke-NTFSPermissionAudit.ps1 first." }
        return $null
    }
    if ($candidates.Count -gt 1) {
        Write-Warning "Multiple $Prefix*.csv files found in '$InputFolder' (output from more than one audit run?). Using the most recent: $($candidates[0].Name). Point -InputFolder at a folder containing just the run you want if this isn't what you intended."
    }
    return $candidates[0].FullName
}

$identityPermsFile = Find-LatestRunFile -Prefix 'IdentityPermissions' -Required
$identityPermsPath = $identityPermsFile
$adDetailsPath     = Find-LatestRunFile -Prefix 'ADIdentityDetails'

# Reuse the source run's timestamp for the default output file name too, so the
# HTML file visibly pairs with the CSVs it was built from. Falls back to "now" if
# the chosen file doesn't match the expected timestamp pattern (e.g. it was the
# legacy fixed-name fallback, or was renamed).
$RunTimestamp = if ($identityPermsFile -match '_(\d{8}_\d{6})\.csv$') { $Matches[1] } else { Get-Date -Format 'yyyyMMdd_HHmmss' }

# Resolve -OutputHtmlPath into a concrete target file path:
#   - a path ending in an existing/creatable file name -> used exactly as given
#   - an existing, EMPTY directory -> a timestamped file name is generated inside it
#   - an existing, NON-empty directory -> error (deliberately -- don't guess a file
#     name into a folder that already has other content in it)
#   - omitted -> defaults inside -InputFolder
if (-not $OutputHtmlPath) {
    $OutputHtmlPath = Join-Path $InputFolder "AccessMap_$RunTimestamp.html"
}
elseif (Test-Path -LiteralPath $OutputHtmlPath -PathType Container) {
    $existingItems = @(Get-ChildItem -LiteralPath $OutputHtmlPath -Force -ErrorAction SilentlyContinue)
    if ($existingItems.Count -gt 0) {
        throw "'$OutputHtmlPath' is an existing, non-empty folder. Specify a full file path for -OutputHtmlPath (e.g. '$(Join-Path $OutputHtmlPath "AccessMap_$RunTimestamp.html")'), or point at a different/empty output location, rather than have this script guess a file name into a folder that already has content."
    }
    $OutputHtmlPath = Join-Path $OutputHtmlPath "AccessMap_$RunTimestamp.html"
}
else {
    $parent = Split-Path -Path $OutputHtmlPath -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

if ((Test-Path -LiteralPath $OutputHtmlPath) -and -not $Force) {
    throw "Output file '$OutputHtmlPath' already exists. Re-run with -Force to overwrite it, or choose a different -OutputHtmlPath."
}

Write-Host "Build-AccessMapHtml v$ScriptVersion" -ForegroundColor Cyan
Write-Host "Reading $identityPermsPath ..." -ForegroundColor Cyan
$permRows = Import-Csv -LiteralPath $identityPermsPath
Write-Verbose "Loaded $($permRows.Count) permission row(s)."

$adDetails = @{}
if ($adDetailsPath -and (Test-Path -LiteralPath $adDetailsPath)) {
    Write-Host "Reading $adDetailsPath ..." -ForegroundColor Cyan
    foreach ($row in (Import-Csv -LiteralPath $adDetailsPath)) {
        if ($row.IdentitySid) { $adDetails[$row.IdentitySid] = $row }
    }
    Write-Verbose "Loaded AD details for $($adDetails.Count) identity(ies)."
}
else {
    Write-Warning "No ADIdentityDetails*.csv found in '$InputFolder'. Identity nodes will show name/type only (no department/manager/account-state info)."
}

#region Build compact index structures -----------------------------------------

# Rights are encoded as a small integer to keep the embedded JSON compact;
# the HTML/JS template's RIGHTS_LABELS array (kept in the same order) turns
# these back into text for display.
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
        groupScope    = if ($detail) { $detail.GroupScope } else { $null }
        memberCount   = if ($detail) { $detail.DirectMemberCount } else { $null }
        managedBy     = if ($detail) { $detail.ManagedBy } else { $null }
        notes     = if ($detail) { $detail.LookupNotes } else { $null }
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

function Get-OrAdd-Folder {
    param([string]$Path)
    if ($folderLookup.ContainsKey($Path)) { return $folderLookup[$Path] }
    $folderIndex.Add([ordered]@{ path = $Path })
    $idx = $folderIndex.Count - 1
    $folderLookup[$Path] = $idx
    return $idx
}

$edges = New-Object System.Collections.Generic.List[object]
$brokenInheritanceFolders = New-Object System.Collections.Generic.HashSet[int]

$i = 0
foreach ($row in $permRows) {
    $i++
    if ($i % 5000 -eq 0) { Write-Progress -Activity 'Building access map' -Status "$i / $($permRows.Count) rows" -PercentComplete (($i / [math]::Max(1,$permRows.Count)) * 100) }

    $identityIdx = Get-OrAdd-Identity -Sid $row.IdentitySid -Name $row.IdentityName -Type $row.IdentityType
    $folderIdx   = Get-OrAdd-Folder -Path $row.Path

    $inheritanceBroken = ConvertTo-Bool $row.InheritanceBrokenHere
    if ($inheritanceBroken) { [void]$brokenInheritanceFolders.Add($folderIdx) }

    $viaIdx = -1
    if ($row.GrantedViaGroup) {
        $viaKey = $row.GrantedViaGroup.ToLowerInvariant()
        if ($identityNameLookup.ContainsKey($viaKey)) { $viaIdx = $identityNameLookup[$viaKey] }
    }

    $edges.Add(@(
        $folderIdx,
        $identityIdx,
        (Get-RightsCode $row.RightsSummary),
        [int](ConvertTo-Bool $row.IsInheritedAce),
        [int]$inheritanceBroken,
        [int](ConvertTo-Bool ($row.AccessControlType -eq 'Deny')),
        $viaIdx
    ))
}
Write-Progress -Activity 'Building access map' -Completed

Write-Host "Identities: $($identityIndex.Count)   Folders: $($folderIndex.Count)   Edges: $($edges.Count)   Broken-inheritance folders: $($brokenInheritanceFolders.Count)" -ForegroundColor Green
if ($edges.Count -gt 150000) {
    Write-Warning "This is a large map ($($edges.Count) edges). The HTML file may be large and the browser may feel sluggish. Consider generating a map per share/subtree instead of the whole server if that happens."
}

#endregion Build compact index structures ---------------------------------------

#region Serialize and emit HTML -------------------------------------------------

$dataObject = [ordered]@{
    identities = $identityIndex
    folders    = $folderIndex
    edges      = $edges
    generatedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    sourceFolder = $InputFolder
    toolkitVersion = $ScriptVersion
}
Write-Verbose "Serializing to JSON..."
$json = $dataObject | ConvertTo-Json -Depth 6 -Compress

$templatePath = Join-Path $PSScriptRoot 'AccessMapTemplate.html'
if (-not (Test-Path -LiteralPath $templatePath)) {
    throw "Template file not found: $templatePath (expected alongside this script)."
}
$template = Get-Content -LiteralPath $templatePath -Raw

$html = $template.Replace('/*__ACCESS_MAP_DATA__*/null', $json).Replace('__MAX_EDGES_PER_NODE__', $MaxEdgesPerNode)

Set-Content -LiteralPath $OutputHtmlPath -Value $html -Encoding UTF8
Write-Host "Access map written to $OutputHtmlPath" -ForegroundColor Green
Write-Host "Open it directly in a browser -- no server required." -ForegroundColor Yellow

#endregion Serialize and emit HTML ----------------------------------------------
