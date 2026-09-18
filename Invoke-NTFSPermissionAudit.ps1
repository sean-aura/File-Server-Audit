#Requires -Version 5.1
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Audits NTFS folder (and optionally file) permissions across one or more root paths,
    resolving AD identities, expanding group membership, detecting broken inheritance,
    and decoding "Special permissions" into their granular rights.

.DESCRIPTION
    Walks each -Path tree (typically the physical UNC path behind a DFS target, e.g.
    \\FS01\Shared\Finance) and for every folder (and file, if -IncludeFiles is used):

      - Captures the ACL, whether inheritance is broken at that object
        ($acl.AreAccessRulesProtected), and every ACE (identity, allow/deny,
        inherited/explicit, inheritance+propagation flags).
      - Decodes each ACE's FileSystemRights into a friendly Windows ACL-UI-style label
        (Full Control / Modify / Read & Execute / Read / Write) or "Special" with the
        exact granular rights listed out.
      - Resolves each identity's SID and object type (User/Group/Computer/Well-known/
        Unresolved) using System.DirectoryServices.AccountManagement (no RSAT AD module
        required).
      - Optionally expands group ACEs to their effective (recursively nested) members,
        so you can see who actually gets access via group membership.

    Produces three primary views from a single pass over the data:

      1. Per-folder-tree view  (FolderPermissions.csv) - one row per ACE per object.
         "What can people do in this folder?"

      2. Per-identity view    (IdentityPermissions.csv) - one row per (identity, path),
         including rows created by group-membership expansion, with a column showing
         which group (if any) granted the access.
         "What does this person/account have access to, anywhere in the tree?"

      3. Identity directory   (ADIdentityDetails.csv) - one row per unique identity
         encountered anywhere in the scan (every ACE and every expanded group member),
         joinable to the two reports above via IdentitySid. Answers "who actually is
         this account" - name, department, title, manager, employee ID, whether the
         account is enabled/locked/expired, password age, and an approximate last-logon
         date - i.e. the information needed to tell whether an account with access is
         still a current employee in a role that should have it.

    Also produces:
      - InheritanceExceptions.csv : every folder where inheritance is broken.
      - Errors.log                : access-denied / path-too-long / other failures,
                                     so a scan never silently misses data.

.PARAMETER Path
    One or more root paths to scan. This can be the physical UNC path (e.g.
    \\FS01\Shared) or the DFS namespace path itself (e.g. \\contoso.com\Public\
    Shared) -- Windows resolves DFS referrals transparently at the file-system
    level, so this script doesn't need any DFS awareness to work correctly
    either way. Pointing at the DFS path is often simplest if you don't have
    (or don't need) visibility into which physical server currently backs it;
    see the companion Get-FileServerShareInventory.ps1 script if you do want
    to confirm/record that mapping first (it works without DFS management
    access too, via -DfsPath).

.PARAMETER IncludeFiles
    By default only folders are scanned (recommended for large shares). Add this
    switch to also capture per-file ACEs where they differ from the folder default
    (i.e. explicit / non-inherited file ACEs are always captured; inherited file
    ACEs are only captured if -IncludeInheritedFileAces is also specified, since on
    most shares every file simply inherits the folder ACL and recording it again
    for every single file is expensive and low-value).

.PARAMETER IncludeInheritedFileAces
    Only meaningful with -IncludeFiles. Also record file-level ACEs that are pure
    inheritance from the parent folder. Very expensive on large trees - use sparingly,
    e.g. scoped to a single suspect folder.

.PARAMETER MaxDepth
    Maximum folder depth to recurse, relative to each -Path root (0 = root only,
    1 = root + immediate subfolders, etc). Default -1 = unlimited. Ignored if
    -NoRecursion is also specified.

.PARAMETER NoRecursion
    Scan only each -Path root itself (and, with -IncludeFiles, the files directly
    in it) -- no subfolders at all. Equivalent to -MaxDepth 0, but clearer to read
    and to script around. Takes precedence over -MaxDepth if both are supplied.

.PARAMETER BreadthFirst
    Scan level by level -- every folder at the current depth before moving to the
    next depth -- instead of the default depth-first order (one branch all the way
    down before backing up to its siblings). Doesn't change what gets scanned or
    the final CSV contents (folder hierarchy in the output is reconstructed from
    each row's own path, not from scan order), only the ORDER objects are visited
    and written. The practical reason to use this: if a scan gets interrupted
    partway through (killed, times out, machine reboots) on a very large tree,
    depth-first leaves you with one fully-scanned branch and nothing else,
    whereas breadth-first leaves you with the top few levels of EVERYTHING --
    usually a far more useful partial result, and it's also what
    Build-AccessMapHtml.ps1's tree view already displays well by default (a
    shallow-but-complete tree, no different from an intentionally
    -MaxDepth-limited run). The trade-off: on a very wide, shallow share (many
    thousands of top-level folders), breadth-first can hold more pending items in
    memory at once than depth-first would, since it visits an entire level before
    going deeper -- rarely significant in practice (each pending item is just a
    path and a depth number), but a real characteristic difference worth knowing.

.PARAMETER ThrottleLimit
    Process this many objects' ACL reads and identity resolution concurrently,
    instead of one at a time. REQUIRES PowerShell 7+ (Core edition) -- the
    underlying mechanism, ForEach-Object -Parallel, does not exist in Windows
    PowerShell 5.1, and this script deliberately does not attempt a hand-rolled
    runspace-pool fallback for 5.1. Passing a value above 1 under Windows
    PowerShell 5.1 is a terminating error with a clear message, not a silent
    no-op or a silent fallback to sequential -- you should always be able to
    tell which mode actually ran.

    Why this helps: on a large share, the bottleneck is almost always I/O
    latency (a network round-trip per ACL read, plus AD round-trips for
    identities/group membership the first time each is seen), not CPU -- so
    running several of these waits concurrently can cut wall-clock time
    substantially, especially over a network (SMB) rather than local disk.

    What actually gets parallelized: directory/file NAME enumeration (cheap,
    used to discover what to scan) stays sequential; only the expensive part --
    reading an object's ACL, resolving each ACE's identity, and expanding groups
    -- is dispatched to a pool of concurrent workers. Two caches are shared
    across all workers via a thread-safe ConcurrentDictionary: a Sid-to-Name/
    Type label cache (used by nearly every ACE) and a group-membership-
    expansion cache (used when -ExpandGroups is set) -- both store only plain
    data (strings), never a live AD Principal object, since those wrap a
    COM-backed DirectoryEntry that isn't safe to use from a thread other than
    the one that resolved it. When a worker needs a full Principal that isn't
    already cached (to expand a group it hasn't seen yet, for instance), it
    resolves it fresh, itself, rather than borrowing one another worker
    produced -- occasionally redundant AD calls across workers on a cold cache,
    by design, in exchange for never touching a not-safe-to-share object across
    threads.

    Default is 1 (fully sequential, identical to how this script has always
    behaved) -- nothing changes unless you explicitly raise this. A reasonable
    starting point when you do is somewhere in the 4-16 range; higher isn't
    always better; a heavily-loaded or older file server can itself become the
    bottleneck (or start throttling/rejecting connections) under too much
    concurrent load, so treat this as a tunable dial to sanity-check against
    your own environment, not a "bigger is always faster" setting.

    Only per-object ACL/identity processing is parallelized in this release --
    the directory-discovery walk itself (and therefore -BreadthFirst/-MaxDepth/
    -NoRecursion's own semantics) is unaffected and unchanged.

    Measured, not assumed: ForEach-Object -Parallel has its own fixed per-item
    overhead (dispatching to a worker, roughly a couple of milliseconds each in
    testing). Whether -ThrottleLimit helps or actively hurts is entirely a
    question of whether your real per-object ACL-read latency exceeds that
    overhead. Against a synthetic per-item delay standing in for a real network
    round-trip (15ms, a plausible SMB latency figure), parallel processing at
    -ThrottleLimit 16 measured roughly 6x faster than sequential for the same
    workload. Against near-zero-latency local work, the fixed per-item overhead
    can make parallel processing measurably SLOWER than sequential, not just
    "no better" -- there is no free lunch here. Benchmark -ThrottleLimit against
    a small, representative sample of your actual share (not the full run)
    before committing to a value for a multi-hour scan; the right answer
    genuinely depends on your network, file server, and AD topology, not just
    the size of the tree.

.PARAMETER ExpandGroups
    Recursively expand each group ACE to its effective members and add rows for
    them in the per-identity report (with GrantedViaGroup populated). Without this
    switch, the per-identity report only shows the groups/users literally present
    on each ACL, not who is inside those groups. This can be slow on large/deeply
    nested groups - member expansion results are cached per group for the run.

.PARAMETER ExpandGroupsExclude
    Group names to skip when expanding (their membership is huge and rarely useful
    for this kind of audit, e.g. "Domain Users", "Everyone", "Authenticated Users").
    Comparison is case-insensitive against the resolved NTAccount short name.

.PARAMETER SkipInheritedAces
    Omit purely-inherited ACEs (keep only explicit ACEs and each folder's own
    inheritance-broken flag) from BOTH FolderPermissions.csv and
    IdentityPermissions.csv -- despite the similarly-named older parameter this
    superseded, it was never folder-report-only; a plain recursive scan
    otherwise repeats the same inherited ACE on every single folder down an
    unbroken inheritance chain (a share with 10,000 folders and 5 inherited
    ACEs each produces ~50,000 near-duplicate rows). Useful once you've
    confirmed the ACL at the top of a share and only want to see where it
    actually changes -- and strongly recommended when the output will feed
    Build-AccessMapHtml.ps1's tree view, since it makes the per-folder access
    counts shown there meaningful (a folder with no row here is "unchanged
    from its parent", not "zero"; any row means "something explicit is set
    here") and keeps the generated HTML file much smaller. -SkipInheritedAcesInFolderReport
    is still accepted as an alias for scripts already using it.

.PARAMETER OutputFolder
    Where the CSV/log files are written. Created if it doesn't exist. Defaults to
    a timestamped folder in the current directory. Every output file name also
    includes the same run timestamp (e.g. FolderPermissions_20260910_211500.csv),
    so re-running into a fixed/shared -OutputFolder across multiple runs never
    overwrites a previous run's files -- each run's complete set of files is
    self-identifying by timestamp even if they get moved out of their original
    folder later. See -Force if you ever need to override the resulting
    don't-overwrite protection.

.PARAMETER NoAdLookup
    Skip AD identity-type resolution and group expansion entirely (fastest option,
    e.g. for a quick first pass or when not running with domain connectivity).
    Identities are still shown by their resolved NTAccount name/SID. ADIdentityDetails.csv
    is still produced but every row will just show Name/Sid/Type with a note that AD
    lookup was disabled, since none of the HR/account-state fields can be populated.

.PARAMETER Force
    Every output file name includes a run timestamp by default (see below), so
    re-running into the same -OutputFolder normally never collides with a previous
    run's files. -Force is only needed in the rare case a file with that exact name
    already exists anyway (e.g. two runs started within the same second); without it,
    the script errors rather than silently overwriting.

.PARAMETER Resume
    Continue a previous run of this exact same command that was interrupted before
    finishing (killed, crashed, the machine rebooted mid-scan) instead of starting
    over from scratch. REQUIRES an explicit -OutputFolder pointing at the SAME
    folder the interrupted run used -- -OutputFolder's default value bakes in the
    current timestamp, so relying on the default here would almost certainly point
    at a brand-new, empty folder with nothing to resume; the script errors clearly
    rather than silently scanning into the wrong place.

    How it works: every run writes a small RunConfig_<timestamp>.json capturing
    every parameter that affects WHAT gets scanned or how (Path, IncludeFiles,
    MaxDepth, BreadthFirst, ExpandGroups, ThrottleLimit, and so on), and a
    Checkpoint_<timestamp>.txt recording every object that's been fully processed
    AND had its rows durably written to the CSVs (never marked complete before
    that, specifically so a crash between "processed" and "written to disk" can't
    silently lose data -- worst case, that one object's work is simply redone).
    -Resume finds the most recent run in -OutputFolder that doesn't have a
    matching Completed_<timestamp>.marker (i.e., didn't finish), validates that
    EVERY tracked parameter from this invocation matches what RunConfig recorded
    -- if anything differs (a different -Path, -ThrottleLimit, -BreadthFirst,
    etc.), it refuses with a clear error listing exactly what changed, rather than
    silently producing a scan that's inconsistent with itself -- then continues
    appending to that same run's CSVs, skipping anything already in the
    checkpoint.

    The trade-off you're accepting by using this (rather than just re-running from
    scratch): anything already scanned before the interruption is NOT re-checked,
    even if it was actually modified in the meantime -- a folder whose permissions
    changed five minutes after it was scanned, then again before the resumed run
    finishes the rest of the tree, would still show its OLDER permissions from the
    first pass. For most large-scan interruption scenarios this is exactly the
    right trade-off (redoing the whole scan costs far more than this staleness
    risk), but it's worth knowing about explicitly.

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -ExpandGroups

    Full folder-only audit of the Finance share, expanding group membership.

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance','\\FS01\Shared\HR' `
        -IncludeFiles -MaxDepth 3 -OutputFolder C:\Audit\Run1

.NOTES
    Version: 0.5.1

    Works under both Windows PowerShell 5.1 and PowerShell 7+ (the ACL-reading code
    path differs internally between the two -- .NET Framework vs .NET Core expose
    that API differently -- but this is handled automatically; no action needed).

    Minimum PowerShell 5.1. Run interactively as (or "runas" / scheduled task under) an
    account with at least Read + Read-Permissions NTFS access to every object being
    scanned, and read access to Active Directory for identity resolution. No RSAT
    ActiveDirectory module is required; System.DirectoryServices.AccountManagement
    (part of the .NET Framework) is used instead.

    ADIdentityDetails.csv's "last logon" column reads the replicated lastLogonTimestamp
    attribute (not the single-DC-only lastLogon attribute), which by design can lag the
    true last logon by up to ~14 days (the default domain replication interval for that
    attribute) - treat it as "roughly this recently", not to-the-day precise, when using
    it to spot dormant accounts. lastLogonTimestamp is also sometimes blank/unpopulated
    depending on domain history and replication state; WhenChanged (AD's general
    last-modified timestamp, updated on essentially any attribute write, not just
    logons) is captured alongside it as a more consistently-available fallback signal
    for "is this account still being touched/maintained".

    KNOWN LIMITATION - very long paths (>~248 chars): .NET Framework's classic
    Directory/File APIs used here are subject to MAX_PATH unless the target OS/.NET
    configuration has long-path support enabled. The script attempts a \\?\UNC\ prefix
    fallback, but if you have deeply nested folders this may still fail; the failure
    is logged to Errors.log rather than aborting the run. Shortening the scan root
    (e.g. via a temporary subst/mapped drive closer to the deep folder) is the usual
    workaround.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    [switch]$IncludeFiles,

    [switch]$IncludeInheritedFileAces,

    [int]$MaxDepth = -1,

    [switch]$NoRecursion,

    [switch]$BreadthFirst,

    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 1,

    [switch]$ExpandGroups,

    [string[]]$ExpandGroupsExclude = @('Domain Users', 'Everyone', 'Authenticated Users', 'Users', 'BUILTIN\Users'),

    [Alias('SkipInheritedAcesInFolderReport')]
    [switch]$SkipInheritedAces,

    [string]$OutputFolder = ".\NTFSAudit_$(Get-Date -Format yyyyMMdd_HHmmss)",

    [switch]$NoAdLookup,

    [switch]$Force,

    [switch]$Resume
)

#region Setup ---------------------------------------------------------------

$ScriptVersion = '0.5.1'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# [System.IO.Directory]::GetAccessControl / [System.IO.File]::GetAccessControl exist as
# static methods only in the full .NET Framework (Windows PowerShell 5.1, "Desktop"
# edition). PowerShell 7+ ("Core" edition) runs on .NET Core/.NET 5+, where the same
# functionality moved to extension methods on DirectoryInfo/FileInfo in
# System.IO.FileSystemAclExtensions -- calling the old static methods there throws
# "does not contain a method named 'GetAccessControl'". Get-ObjectAcl below branches on
# this so the script works correctly under both 5.1 and 7+.
$script:IsPSCore = $PSVersionTable.PSEdition -eq 'Core'

if ($ThrottleLimit -gt 1 -and -not $script:IsPSCore) {
    throw "-ThrottleLimit $ThrottleLimit requires PowerShell 7+ (parallel processing uses ForEach-Object -Parallel, which does not exist in Windows PowerShell 5.1). Currently running under the '$($PSVersionTable.PSEdition)' edition, PowerShell $($PSVersionTable.PSVersion). Either run this script under 'pwsh' (PS7+), or omit -ThrottleLimit / leave it at the default of 1 to continue running sequentially under Windows PowerShell 5.1."
}

# Shared, thread-safe caches used only when -ThrottleLimit > 1. Deliberately
# hold only plain data (Sid -> Name/Type strings; GroupSid -> array of member
# Name/Sid/Type), never a live AD Principal/DirectoryEntry object -- those wrap
# a COM object that is not safe to use from a thread other than the one that
# resolved it. See Resolve-IdentityInfo / Get-EffectiveGroupMembers for how
# these are consumed.
if ($ThrottleLimit -gt 1) {
    $script:SharedLabelCache = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
    $script:SharedGroupCache = [System.Collections.Concurrent.ConcurrentDictionary[string,object]]::new()
}
if ($script:IsPSCore) {
    try { Add-Type -AssemblyName System.IO.FileSystem.AccessControl -ErrorAction Stop }
    catch { Write-Warning "Could not load System.IO.FileSystem.AccessControl ($($_.Exception.Message)). ACL reads will likely fail on this PowerShell 7+ session." }
}

if ($NoRecursion) {
    if ($PSBoundParameters.ContainsKey('MaxDepth') -and $MaxDepth -ne 0) {
        Write-Warning "-NoRecursion was specified along with -MaxDepth $MaxDepth; -NoRecursion takes precedence (each root will be scanned at depth 0 only)."
    }
    $MaxDepth = 0
}
Write-Verbose "Effective settings: MaxDepth=$MaxDepth  IncludeFiles=$IncludeFiles  IncludeInheritedFileAces=$IncludeInheritedFileAces  ExpandGroups=$ExpandGroups  NoAdLookup=$NoAdLookup"

if ($Resume -and -not $PSBoundParameters.ContainsKey('OutputFolder')) {
    throw "-Resume requires an explicit -OutputFolder pointing at the SAME folder the interrupted run used. -OutputFolder's default value bakes in the current timestamp, so without an explicit value here, -Resume would almost certainly look in a brand-new, empty folder rather than the one you meant to continue."
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    if ($Resume) { throw "-Resume was specified but -OutputFolder '$OutputFolder' does not exist -- nothing to resume there." }
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

# Every parameter that affects WHAT gets scanned or HOW -- not cosmetic things
# like -Force. Sorted/normalized so two equivalent invocations (e.g. -NoRecursion
# vs. an explicit -MaxDepth 0, or -Path roots given in a different order) compare
# equal rather than failing a resume over a difference that doesn't actually
# change the scan.
function Get-EffectiveRunConfig {
    [ordered]@{
        Path                     = @($Path | Sort-Object)
        IncludeFiles             = [bool]$IncludeFiles
        IncludeInheritedFileAces = [bool]$IncludeInheritedFileAces
        MaxDepth                 = $MaxDepth
        BreadthFirst             = [bool]$BreadthFirst
        ThrottleLimit            = $ThrottleLimit
        ExpandGroups             = [bool]$ExpandGroups
        ExpandGroupsExclude      = @($ExpandGroupsExclude | Sort-Object)
        SkipInheritedAces        = [bool]$SkipInheritedAces
        NoAdLookup               = [bool]$NoAdLookup
    }
}
$effectiveConfig = Get-EffectiveRunConfig

if ($Resume) {
    # Find the most recent run in this folder that has a RunConfig but no
    # matching Completed marker -- i.e., started but never finished. Sorted by
    # the timestamp embedded in the filename (not filesystem LastWriteTime),
    # same reasoning as Build-AccessMapHtml.ps1's file discovery: filesystem
    # metadata can disagree with which run a file actually belongs to.
    $runConfigCandidates = @(Get-ChildItem -LiteralPath $OutputFolder -Filter 'RunConfig_*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^RunConfig_(\d{8}_\d{6})\.json$' } |
        Sort-Object -Descending -Property @{ Expression = { $Matches[1] } })

    $resumeTarget = $null
    foreach ($candidate in $runConfigCandidates) {
        $ts = [regex]::Match($candidate.Name, '^RunConfig_(\d{8}_\d{6})\.json$').Groups[1].Value
        $markerPath = Join-Path $OutputFolder "Completed_$ts.marker"
        if (-not (Test-Path -LiteralPath $markerPath)) {
            $resumeTarget = @{ Timestamp = $ts; ConfigPath = $candidate.FullName }
            break
        }
    }
    if (-not $resumeTarget) {
        throw "-Resume was specified but no incomplete run was found in '$OutputFolder' (either there's no previous run here at all, or every run here already finished -- check for a RunConfig_*.json with no matching Completed_*.marker). Omit -Resume to start a fresh run."
    }

    $savedConfig = Get-Content -LiteralPath $resumeTarget.ConfigPath -Raw | ConvertFrom-Json
    $mismatches = New-Object System.Collections.Generic.List[string]
    foreach ($key in $effectiveConfig.Keys) {
        $savedVal = $savedConfig.$key
        $currentVal = $effectiveConfig[$key]
        # ConvertFrom-Json turns a saved array into an array too, but comparing
        # arrays with -ne / -eq is unreliable in PowerShell, so compare their
        # joined-string form -- fine here since these are all short lists of
        # simple strings/paths, not data where that could hide a real difference.
        $savedCmp   = if ($savedVal -is [array]) { ($savedVal -join '|') } else { "$savedVal" }
        $currentCmp = if ($currentVal -is [array]) { ($currentVal -join '|') } else { "$currentVal" }
        if ($savedCmp -ne $currentCmp) {
            $mismatches.Add("  -$key : was [$savedCmp], now [$currentCmp]")
        }
    }
    if ($mismatches.Count -gt 0) {
        throw "-Resume was specified, but this invocation's parameters don't match the run being resumed (RunConfig_$($resumeTarget.Timestamp).json). Resuming with different parameters would produce a scan that's inconsistent with itself, so this refuses rather than guessing which settings should win. Differences found:`n$($mismatches -join "`n")`nEither match the original invocation exactly, or omit -Resume to start a fresh run (in a different -OutputFolder, or with -Force in this one)."
    }

    $RunTimestamp = $resumeTarget.Timestamp
    Write-Host "Resuming run $RunTimestamp (all parameters match; continuing where it left off)." -ForegroundColor Cyan
}
else {
    $RunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
}

$FolderReportPath      = Join-Path $OutputFolder "FolderPermissions_$RunTimestamp.csv"
$IdentityReportPath    = Join-Path $OutputFolder "IdentityPermissions_$RunTimestamp.csv"
$InheritanceExceptions = Join-Path $OutputFolder "InheritanceExceptions_$RunTimestamp.csv"
$IdentityDetailsPath   = Join-Path $OutputFolder "ADIdentityDetails_$RunTimestamp.csv"
$ErrorLogPath          = Join-Path $OutputFolder "Errors_$RunTimestamp.log"
$RunConfigPath         = Join-Path $OutputFolder "RunConfig_$RunTimestamp.json"
$CheckpointPath        = Join-Path $OutputFolder "Checkpoint_$RunTimestamp.txt"
$CompletedMarkerPath   = Join-Path $OutputFolder "Completed_$RunTimestamp.marker"

# $script:CompletedPaths / $script:HeaderWritten flags for the three main CSVs
# are all set up below, branching on fresh-vs-resumed, before the collision
# check -- a resumed run is SUPPOSED to find its own files already there.
$script:CompletedItemPaths = New-Object System.Collections.Generic.HashSet[string]
if ($Resume) {
    if (Test-Path -LiteralPath $CheckpointPath) {
        foreach ($line in (Get-Content -LiteralPath $CheckpointPath)) {
            if ($line) { [void]$script:CompletedItemPaths.Add($line) }
        }
    }
    Write-Host "Loaded checkpoint: $($script:CompletedItemPaths.Count) object(s) already completed and will be skipped." -ForegroundColor Cyan
    # The files already exist with headers from the original run -- Flush-Buffers
    # must APPEND from the first flush onward, never re-create/overwrite them.
    $script:FolderHeaderWritten   = $true
    $script:IdentityHeaderWritten = $true
    $script:InheritHeaderWritten  = $true
}
else {
    # Because names are timestamped, a collision should only happen if two runs
    # somehow started in the same second targeting the same folder. Rather than
    # silently overwrite (the previous behavior when -OutputFolder was reused),
    # refuse and require -Force -- an accidental silent overwrite of audit
    # evidence is worse than a rare, easily-retried error.
    $existingOutputs = @(@($FolderReportPath, $IdentityReportPath, $InheritanceExceptions, $IdentityDetailsPath, $ErrorLogPath) |
        Where-Object { Test-Path -LiteralPath $_ })
    if ($existingOutputs.Count -gt 0 -and -not $Force) {
        throw "Output file(s) already exist and -Force was not specified: $($existingOutputs -join ', '). This is unusual given the timestamped filenames -- if you intend to overwrite them, re-run with -Force."
    }
    if ($existingOutputs.Count -gt 0 -and $Force) {
        Write-Warning "Overwriting $($existingOutputs.Count) existing output file(s) because -Force was specified."
        foreach ($f in $existingOutputs) { Remove-Item -LiteralPath $f -Force }
    }
    $effectiveConfig | ConvertTo-Json | Set-Content -LiteralPath $RunConfigPath -Encoding UTF8
    $script:FolderHeaderWritten   = $false
    $script:IdentityHeaderWritten = $false
    $script:InheritHeaderWritten  = $false
}

$adAvailable = $false
if (-not $NoAdLookup) {
    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $script:PrincipalCtx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain')
        $adAvailable = $true
        Write-Verbose "AD identity resolution available via PrincipalContext ($($script:PrincipalCtx.ConnectedServer))."
    }
    catch {
        Write-Warning "Could not initialise AD PrincipalContext ($($_.Exception.Message)). Continuing with -NoAdLookup behaviour (identities shown as NTAccount/SID only)."
    }
}

# Caches, keyed by SID string, so we never resolve/expand the same identity twice.
$script:IdentityCache = @{}
$script:GroupMemberCache = @{}
# Keyed by manager/managedBy distinguished name -> resolved display name.
$script:ManagerNameCache = @{}

function Write-AuditError {
    param([string]$ItemPath, [string]$Message)
    $line = "[{0}] {1} :: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $ItemPath, $Message
    Add-Content -LiteralPath $ErrorLogPath -Value $line
    Write-Warning $line
}

#endregion Setup --------------------------------------------------------------

#region Helper functions -------------------------------------------------------

function Get-LongPathSafe {
    <#
        Returns a path usable with classic .NET IO APIs, applying the \\?\ / \\?\UNC\
        long-path prefix when the path is close to MAX_PATH. Leaves short paths untouched
        so drive-relative behaviour is unaffected.
    #>
    param([Parameter(Mandatory)][string]$InputPath)

    if ($InputPath.Length -lt 240 -or $InputPath.StartsWith('\\?\')) {
        return $InputPath
    }
    if ($InputPath.StartsWith('\\')) {
        return '\\?\UNC\' + $InputPath.Substring(2)
    }
    return '\\?\' + $InputPath
}

function Resolve-IdentityInfo {
    <#
        Resolves an IdentityReference (as found on an ACE) to name/SID/type,
        using System.DirectoryServices.AccountManagement. Falls back gracefully
        for well-known SIDs (Everyone, SYSTEM, BUILTIN\Administrators, etc.) and
        for anything AD can't resolve (orphaned SIDs, cross-forest, etc.).

        -Cache defaults to the persistent $script:IdentityCache used by the
        sequential scan. Under -ThrottleLimit parallel processing, callers pass
        a fresh, empty, per-item hashtable instead (each parallel item gets a
        completely isolated scope -- ForEach-Object -Parallel does not persist
        any state across items even when a runspace/thread is reused, verified
        directly rather than assumed) plus -SharedLabelCache, a thread-safe
        ConcurrentDictionary shared across every worker. -SharedLabelCache
        deliberately stores only plain data (Sid/Name/Type strings), never the
        live .Principal object -- an AD Principal wraps a COM-backed
        DirectoryEntry that is not safe to use from a runspace other than the
        one that resolved it, so sharing it directly across threads would risk
        subtle corruption rather than just a missed cache hit.
    #>
    param(
        [Parameter(Mandatory)]$IdentityReference,
        $Cache = $script:IdentityCache,
        $SharedLabelCache = $null
    )

    # Normalise to a SecurityIdentifier so we have a stable cache key regardless
    # of whether the underlying ACE stored an NTAccount or a SID.
    try {
        $sid = if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            $IdentityReference
        }
        else {
            $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
        }
    }
    catch {
        return [PSCustomObject]@{
            Name   = $IdentityReference.ToString()
            Sid    = $null
            Type   = 'Unresolved'
        }
    }

    $sidStr = $sid.Value
    if ($Cache.ContainsKey($sidStr)) {
        Write-Verbose "Identity cache hit: $sidStr"
        return $Cache[$sidStr]
    }
    if ($null -ne $SharedLabelCache -and $SharedLabelCache.ContainsKey($sidStr)) {
        # Fast path: reuse a Name/Type label another parallel worker already
        # resolved. .Principal stays $null here -- if THIS item later needs
        # the full Principal (to expand a group's members), it falls through
        # to a fresh AD lookup at that point rather than using a borrowed,
        # unsafe-to-share object.
        $label = $SharedLabelCache[$sidStr]
        $result = [PSCustomObject]@{ Name = $label.Name; Sid = $sidStr; Type = $label.Type; Principal = $null }
        $Cache[$sidStr] = $result
        Write-Verbose "Identity shared-label-cache hit: $sidStr"
        return $result
    }

    $name = $sidStr
    try { $name = $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { }

    $type = 'Unresolved'
    $principalObj = $null

    if ($sid.IsWellKnown([System.Security.Principal.WellKnownSidType]::WorldSid) -or
        $sid.Value -match '^S-1-5-(7|18|19|20)$' -or
        $name -match '^(NT AUTHORITY|BUILTIN)\\') {
        $type = 'Well-known / Local'
    }
    elseif ($adAvailable) {
        try {
            $principalObj = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(
                $script:PrincipalCtx, [System.DirectoryServices.AccountManagement.IdentityType]::Sid, $sidStr)
            if ($principalObj) {
                $type = switch ($principalObj.GetType().Name) {
                    'UserPrincipal'      { 'User' }
                    'GroupPrincipal'     { 'Group' }
                    'ComputerPrincipal'  { 'Computer' }
                    default              { $principalObj.GetType().Name }
                }
                if ($principalObj.SamAccountName) {
                    $name = "$($principalObj.Context.Name)\$($principalObj.SamAccountName)"
                }
            }
        }
        catch {
            # Cross-domain / cross-forest identities frequently fail FindByIdentity
            # against a single-domain PrincipalContext; that's expected, not fatal.
        }
    }

    $result = [PSCustomObject]@{
        Name      = $name
        Sid       = $sidStr
        Type      = $type
        Principal = $principalObj   # kept only for in-process group expansion; not exported
    }
    $Cache[$sidStr] = $result
    if ($null -ne $SharedLabelCache) { $SharedLabelCache[$sidStr] = [PSCustomObject]@{ Name = $name; Type = $type } }
    Write-Verbose "Resolved identity $sidStr -> $name ($type)"
    return $result
}

function Get-EffectiveGroupMembers {
    <#
        Recursively expands a GroupPrincipal to its effective members using
        GetMembers($true), which itself handles nested-group flattening.
        Returns an array of [PSCustomObject]@{Name; Sid; Type} for USER/COMPUTER
        leaf members only (nested groups are not emitted as rows themselves --
        only their resolved members are -- since the per-identity report is meant
        to answer "which end accounts have access").

        -GroupCache/-Cache default to the persistent sequential-scan caches.
        Under parallel processing, -SharedGroupCache (a thread-safe
        ConcurrentDictionary of plain Name/Sid/Type member lists, safe to share)
        is checked first; on a miss, the actual expensive GetMembers($true) call
        still needs to happen using THIS item's own .Principal (never a
        Principal borrowed from another thread's cache), same reasoning as
        Resolve-IdentityInfo's -SharedLabelCache.
    #>
    param(
        [Parameter(Mandatory)]$IdentityInfo,
        $Cache = $script:IdentityCache,
        $GroupCache = $script:GroupMemberCache,
        $SharedGroupCache = $null,
        $SharedLabelCache = $null
    )

    if ($IdentityInfo.Type -ne 'Group' -or -not $IdentityInfo.Principal) { return @() }

    $sidStr = $IdentityInfo.Sid
    if ($GroupCache.ContainsKey($sidStr)) {
        Write-Verbose "Group member cache hit: $($IdentityInfo.Name)"
        return $GroupCache[$sidStr]
    }
    if ($null -ne $SharedGroupCache -and $SharedGroupCache.ContainsKey($sidStr)) {
        Write-Verbose "Group member shared-cache hit: $($IdentityInfo.Name)"
        $result = $SharedGroupCache[$sidStr]
        $GroupCache[$sidStr] = $result
        return $result
    }

    Write-Verbose "Expanding group membership (recursive): $($IdentityInfo.Name)"
    $members = New-Object System.Collections.Generic.List[object]
    try {
        $groupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]$IdentityInfo.Principal
        foreach ($m in $groupPrincipal.GetMembers($true)) {
            $memberSidStr = $m.Sid.Value

            # Reuse (or populate) the same identity cache Resolve-IdentityInfo uses, so
            # every expanded member -- not just directly-ACE'd identities -- ends up in
            # the final ADIdentityDetails.csv report with a Principal reference to pull
            # department/manager/account-state details from.
            if ($Cache.ContainsKey($memberSidStr)) {
                $cached = $Cache[$memberSidStr]
            }
            else {
                $memberType = switch ($m.GetType().Name) {
                    'UserPrincipal'     { 'User' }
                    'ComputerPrincipal' { 'Computer' }
                    default             { $m.GetType().Name }
                }
                $cached = [PSCustomObject]@{
                    Name      = "$($m.Context.Name)\$($m.SamAccountName)"
                    Sid       = $memberSidStr
                    Type      = $memberType
                    Principal = $m
                }
                $Cache[$memberSidStr] = $cached
                if ($null -ne $SharedLabelCache) { $SharedLabelCache[$memberSidStr] = [PSCustomObject]@{ Name = $cached.Name; Type = $cached.Type } }
                Write-Verbose "Resolved identity $memberSidStr -> $($cached.Name) ($($cached.Type)) [via group expansion]"
            }

            $members.Add([PSCustomObject]@{
                Name = $cached.Name
                Sid  = $cached.Sid
                Type = $cached.Type
            })
        }
    }
    catch {
        Write-AuditError -ItemPath "Group:$($IdentityInfo.Name)" -Message "Failed to expand membership: $($_.Exception.Message)"
    }

    $result = $members.ToArray()
    $GroupCache[$sidStr] = $result
    if ($null -ne $SharedGroupCache) { $SharedGroupCache[$sidStr] = $result }
    Write-Verbose "Group $($IdentityInfo.Name) expanded to $($result.Count) effective member(s)"
    return $result
}

function Resolve-ManagerName {
    <#
        Resolves a manager/managedBy distinguished name to a friendly display name
        via a direct ADSI bind (cheaper than another PrincipalContext search, and
        works for the raw DN string AD stores in the 'manager'/'managedBy' attributes).
        Cached per DN since many users share the same manager.
    #>
    param([Parameter(Mandatory)][string]$DistinguishedName)

    if ($script:ManagerNameCache.ContainsKey($DistinguishedName)) {
        return $script:ManagerNameCache[$DistinguishedName]
    }

    $name = $DistinguishedName
    try {
        $managerEntry = [ADSI]"LDAP://$DistinguishedName"
        if ($managerEntry.Properties['displayName'].Value) {
            $name = $managerEntry.Properties['displayName'].Value
        }
        elseif ($managerEntry.Properties['cn'].Value) {
            $name = $managerEntry.Properties['cn'].Value
        }
    }
    catch {
        Write-AuditError -ItemPath 'Manager lookup' -Message "Failed to resolve '$DistinguishedName': $($_.Exception.Message)"
    }

    $script:ManagerNameCache[$DistinguishedName] = $name
    return $name
}

function Convert-AdLargeInteger {
    <#
        AD stores 64-bit values (lastLogonTimestamp, accountExpires, etc.) as
        IADsLargeInteger COM objects with separate HighPart/LowPart 32-bit halves
        rather than a single .NET Int64. Reassembled here with pure Int64 bitwise
        shift/OR (NOT double-precision arithmetic -- these values regularly exceed
        2^53, the point past which doubles can no longer represent every integer
        exactly, so multiplying HighPart by 2^32 as a double silently rounds to the
        wrong file time). Returns $null for unset/zero/"never" sentinel values
        rather than throwing.
    #>
    param($LargeInt)

    if ($null -eq $LargeInt) { return $null }
    try {
        $high = [int64]$LargeInt.HighPart
        $low  = [int64]$LargeInt.LowPart
        if ($low -lt 0) { $low = $low + 4294967296L }   # LowPart is a signed 32-bit value; rebias to unsigned
        $fileTime = ($high -shl 32) -bor $low
        if ($fileTime -le 0) { return $null }
        return [DateTime]::FromFileTimeUtc($fileTime)
    }
    catch {
        return $null
    }
}

function Get-AdIdentityDetailRow {
    <#
        Builds one row of ADIdentityDetails.csv for a cached identity: the HR/role
        context (department, title, manager, employee ID) and account-state context
        (enabled/locked/expired, password age, approximate last logon) needed to judge
        whether an account that currently has file-system access still should.
        Every field is best-effort and wrapped individually so one missing/unreadable
        attribute never blanks out the rest of the row.
    #>
    param([Parameter(Mandatory)]$IdentityInfo)

    $row = [ordered]@{
        IdentityName             = $IdentityInfo.Name
        IdentitySid              = $IdentityInfo.Sid
        IdentityType             = $IdentityInfo.Type
        SamAccountName           = $null
        DistinguishedName        = $null
        DisplayName              = $null
        EmailAddress             = $null
        Title                    = $null
        Department               = $null
        Office                   = $null
        TelephoneNumber          = $null
        Manager                  = $null
        EmployeeId               = $null
        Description              = $null
        Enabled                  = $null
        LockedOut                = $null
        PasswordNeverExpires     = $null
        PasswordLastSet          = $null
        LastLogonTimestampApprox = $null
        AccountExpirationDate    = $null
        WhenCreated              = $null
        WhenChanged              = $null
        OperatingSystem          = $null
        GroupScope               = $null
        GroupCategory            = $null
        DirectMemberCount        = $null
        ManagedBy                = $null
        LookupNotes              = $null
    }

    if (-not $adAvailable) {
        $row.LookupNotes = 'AD lookup disabled (-NoAdLookup); only Name/Sid/Type available.'
        return [PSCustomObject]$row
    }
    if (-not $IdentityInfo.Principal) {
        $row.LookupNotes = 'No AD object resolved (well-known/local SID, or unresolved/orphaned SID).'
        return [PSCustomObject]$row
    }

    $principal = $IdentityInfo.Principal
    try { $row.SamAccountName    = $principal.SamAccountName }    catch { }
    try { $row.DistinguishedName = $principal.DistinguishedName } catch { }
    try { $row.Description       = $principal.Description }      catch { }

    $de = $null
    try { $de = $principal.GetUnderlyingObject() -as [System.DirectoryServices.DirectoryEntry] }
    catch { Write-AuditError -ItemPath "Identity:$($IdentityInfo.Name)" -Message "Failed to get underlying DirectoryEntry: $($_.Exception.Message)" }

    if ($IdentityInfo.Type -in @('User', 'Computer')) {
        try { $row.DisplayName           = $principal.DisplayName }           catch { }
        try { $row.EmailAddress          = $principal.EmailAddress }          catch { }
        try { $row.Enabled               = $principal.Enabled }               catch { }
        try { $row.PasswordNeverExpires  = $principal.PasswordNeverExpires }  catch { }
        try { $row.PasswordLastSet       = $principal.LastPasswordSet }       catch { }
        try { $row.AccountExpirationDate = $principal.AccountExpirationDate } catch { }
        try { $row.LockedOut             = $principal.IsAccountLockedOut() }  catch { }

        if ($de) {
            try { if ($de.Properties['title'].Value)             { $row.Title           = $de.Properties['title'].Value } }             catch { }
            try { if ($de.Properties['department'].Value)        { $row.Department      = $de.Properties['department'].Value } }        catch { }
            try { if ($de.Properties['physicalDeliveryOfficeName'].Value) { $row.Office  = $de.Properties['physicalDeliveryOfficeName'].Value } } catch { }
            try { if ($de.Properties['telephoneNumber'].Value)   { $row.TelephoneNumber = $de.Properties['telephoneNumber'].Value } }    catch { }
            try { if ($de.Properties['employeeID'].Value)        { $row.EmployeeId      = $de.Properties['employeeID'].Value } }         catch { }
            try { if ($de.Properties['operatingSystem'].Value)   { $row.OperatingSystem = $de.Properties['operatingSystem'].Value } }    catch { }
            try { if ($de.Properties['whenCreated'].Value)       { $row.WhenCreated     = [datetime]$de.Properties['whenCreated'].Value } } catch { }
            # whenChanged updates on essentially any attribute write (password changes,
            # group membership changes, admin edits, etc., not just logons) and is far
            # more consistently populated across AD environments than
            # lastLogonTimestamp -- useful as a "this account is still active/maintained"
            # signal even when the logon timestamp itself is blank or stale.
            try { if ($de.Properties['whenChanged'].Value)       { $row.WhenChanged     = [datetime]$de.Properties['whenChanged'].Value } } catch { }
            try {
                if ($de.Properties['lastLogonTimestamp'].Value) {
                    $row.LastLogonTimestampApprox = Convert-AdLargeInteger -LargeInt $de.Properties['lastLogonTimestamp'].Value
                }
            } catch { }
            try {
                $managerDn = $de.Properties['manager'].Value
                if ($managerDn) { $row.Manager = Resolve-ManagerName -DistinguishedName $managerDn }
            } catch { }
        }
    }
    elseif ($IdentityInfo.Type -eq 'Group') {
        try {
            $grp = [System.DirectoryServices.AccountManagement.GroupPrincipal]$principal
            $row.GroupScope    = $grp.GroupScope
            $row.GroupCategory = if ($grp.IsSecurityGroup) { 'Security' } else { 'Distribution' }
        } catch { }

        if ($de) {
            # Reading the raw multi-valued 'member' attribute's count avoids resolving
            # every individual member principal just to size the group.
            try { $row.DirectMemberCount = $de.Properties['member'].Count } catch { }
            try {
                $managedByDn = $de.Properties['managedBy'].Value
                if ($managedByDn) { $row.ManagedBy = Resolve-ManagerName -DistinguishedName $managedByDn }
            } catch { }
            try { if ($de.Properties['whenCreated'].Value) { $row.WhenCreated = [datetime]$de.Properties['whenCreated'].Value } } catch { }
            try { if ($de.Properties['whenChanged'].Value) { $row.WhenChanged = [datetime]$de.Properties['whenChanged'].Value } } catch { }
        }
    }

    return [PSCustomObject]$row
}

# Known composite FileSystemRights combinations, matching the checkboxes shown
# on the Windows "Basic Permissions" ACL editor UI. The Synchronize bit is
# ignored when matching (masked off both sides) because Windows sets/clears it
# inconsistently depending on how the ACE was authored, without it changing the
# effective "friendly" permission level shown in the UI.
$script:SynchronizeFlag = [System.Security.AccessControl.FileSystemRights]::Synchronize
$script:RightsCombos = [ordered]@{
    'Full Control'   = [System.Security.AccessControl.FileSystemRights]::FullControl
    'Modify'         = [System.Security.AccessControl.FileSystemRights]::Modify
    'Read & Execute' = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    'Read'           = [System.Security.AccessControl.FileSystemRights]::Read
    'Write'          = [System.Security.AccessControl.FileSystemRights]::Write
}

function Convert-RightsToFriendly {
    <#
        Decodes a FileSystemRights value into the same "basic permission" label
        the Windows ACL editor would show, or 'Special' plus the granular rights
        list if it doesn't exactly match one of the basic combinations.
    #>
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights)

    $masked = $Rights -band (-bnot $script:SynchronizeFlag)

    foreach ($comboName in $script:RightsCombos.Keys) {
        $comboMasked = $script:RightsCombos[$comboName] -band (-bnot $script:SynchronizeFlag)
        if ($masked -eq $comboMasked) {
            return [PSCustomObject]@{
                Summary   = $comboName
                IsSpecial = $false
                Detail    = $Rights.ToString()
            }
        }
    }

    return [PSCustomObject]@{
        Summary   = 'Special'
        IsSpecial = $true
        Detail    = $masked.ToString()
    }
}

function Get-InheritanceDescription {
    <#
        Translates InheritanceFlags + PropagationFlags into the same plain-English
        "applies to" text used in the Windows ACL editor's advanced view.
    #>
    param(
        [System.Security.AccessControl.InheritanceFlags]$InheritanceFlags,
        [System.Security.AccessControl.PropagationFlags]$PropagationFlags
    )

    $ci = $InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $oi = $InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $io = $PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $np = $PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit

    $base = if ($ci -and $oi) { 'This folder, subfolders and files' }
            elseif ($ci)       { 'This folder and subfolders' }
            elseif ($oi)       { 'This folder and files' }
            else               { 'This folder only' }

    if ($io -and $base -ne 'This folder only') {
        $base = $base -replace '^This folder(, | and )?', ''
        $base = if ($base) { $base } else { 'Subfolders and files only' }
    }
    if ($np) { $base += ' (not propagated further)' }
    return $base
}

function Get-ObjectAcl {
    <#
        Wraps the ACL retrieval with the long-path fallback, returning $null (and
        logging) on failure rather than throwing, so a single bad object never
        aborts the whole tree walk.

        Branches on PS edition: Windows PowerShell 5.1 (Desktop, full .NET
        Framework) has GetAccessControl as static methods on Directory/File.
        PowerShell 7+ (Core, .NET Core/.NET 5+) moved this to extension methods
        on DirectoryInfo/FileInfo instead -- calling the old static methods there
        throws "does not contain a method named 'GetAccessControl'".

        -ErrorCollector is optional: when $null (the sequential default), errors
        are logged immediately via Write-AuditError exactly as before. Under
        parallel processing, callers pass a per-item list instead, so the actual
        file write happens once, back on the main thread, after this item's
        result streams back -- multiple threads calling Add-Content on the same
        file concurrently is not something to rely on being safe.
    #>
    param([Parameter(Mandatory)][string]$ItemPath, [Parameter(Mandatory)][bool]$IsDirectory, $ErrorCollector = $null)

    $safePath = Get-LongPathSafe -InputPath $ItemPath
    Write-Verbose "Reading ACL: $ItemPath"
    try {
        if ($script:IsPSCore) {
            if ($IsDirectory) {
                $di = New-Object System.IO.DirectoryInfo($safePath)
                return [System.IO.FileSystemAclExtensions]::GetAccessControl($di)
            }
            else {
                $fi = New-Object System.IO.FileInfo($safePath)
                return [System.IO.FileSystemAclExtensions]::GetAccessControl($fi)
            }
        }
        else {
            if ($IsDirectory) {
                return [System.IO.Directory]::GetAccessControl($safePath)
            }
            else {
                return [System.IO.File]::GetAccessControl($safePath)
            }
        }
    }
    catch [System.UnauthorizedAccessException] {
        if ($null -ne $ErrorCollector) { $ErrorCollector.Add(@{ ItemPath = $ItemPath; Message = 'Access denied reading ACL.' }) }
        else { Write-AuditError -ItemPath $ItemPath -Message 'Access denied reading ACL.' }
    }
    catch {
        $msg = "Failed reading ACL: $($_.Exception.Message)"
        if ($null -ne $ErrorCollector) { $ErrorCollector.Add(@{ ItemPath = $ItemPath; Message = $msg }) }
        else { Write-AuditError -ItemPath $ItemPath -Message $msg }
    }
    return $null
}

#endregion Helper functions ----------------------------------------------------

#region Core per-object processing ---------------------------------------------

# Buffers, flushed to CSV in batches to keep memory bounded on large trees.
$script:FolderRows   = New-Object System.Collections.Generic.List[object]
$script:IdentityRows = New-Object System.Collections.Generic.List[object]
$script:InheritRows  = New-Object System.Collections.Generic.List[object]
$script:PendingCompletedPaths = New-Object System.Collections.Generic.List[string]
$script:FlushEvery    = 2000
$script:FolderHeaderWritten   = $false
$script:IdentityHeaderWritten = $false
$script:InheritHeaderWritten  = $false

function Flush-Buffers {
    <#
        All four buffers (three CSV row-lists plus pending checkpoint paths)
        flush TOGETHER as one unit, triggered by how many ITEMS have completed
        since the last flush -- not by each buffer's own row count
        independently. This matters for -Resume correctness: an item can
        legitimately produce rows in one CSV and none in another (or none at
        all, e.g. every one of its ACEs got filtered out by
        -SkipInheritedAces), so a per-buffer trigger could flush
        FolderRows/IdentityRows while an item's checkpoint entry -- which must
        only ever be written once ALL of that item's row data (if any) is
        confirmed on disk -- gets left pending. Flushing everything as one
        unit sidesteps that entirely: checkpoint paths are always written
        last, after all three CSVs, so a crash between "processed" and
        "written to disk" can never leave a path marked complete whose data
        was actually lost -- worst case, whatever's still pending gets redone
        on resume, which is always safe.
    #>
    param([switch]$Force)

    if (-not ($Force -or $script:PendingCompletedPaths.Count -ge $script:FlushEvery)) { return }

    if ($script:FolderRows.Count -gt 0) {
        Write-Verbose "Flushing $($script:FolderRows.Count) row(s) to $FolderReportPath"
        $script:FolderRows | Export-Csv -LiteralPath $FolderReportPath -NoTypeInformation -Append:$script:FolderHeaderWritten
        $script:FolderHeaderWritten = $true
        $script:FolderRows.Clear()
    }
    if ($script:IdentityRows.Count -gt 0) {
        $script:IdentityRows | Export-Csv -LiteralPath $IdentityReportPath -NoTypeInformation -Append:$script:IdentityHeaderWritten
        $script:IdentityHeaderWritten = $true
        $script:IdentityRows.Clear()
    }
    if ($script:InheritRows.Count -gt 0) {
        $script:InheritRows | Export-Csv -LiteralPath $InheritanceExceptions -NoTypeInformation -Append:$script:InheritHeaderWritten
        $script:InheritHeaderWritten = $true
        $script:InheritRows.Clear()
    }
    if ($script:PendingCompletedPaths.Count -gt 0) {
        Add-Content -LiteralPath $CheckpointPath -Value $script:PendingCompletedPaths
        $script:PendingCompletedPaths.Clear()
    }
}

function Get-ItemAuditRows {
    <#
        Computes every row (folder/identity/inheritance-exception) and any
        errors for ONE file-system object, and RETURNS them rather than
        touching any shared buffer directly -- this is what makes the object
        safe to compute on a worker thread under -ThrottleLimit: the caller
        (always the main thread, whether processing the return value
        immediately in sequential mode or after it streams back from a
        parallel worker) is the only thing that ever appends to
        $script:FolderRows/$script:IdentityRows/$script:InheritRows or writes
        to the error log, so those never need to be made thread-safe.

        -Cache/-GroupCache/-SharedLabelCache/-SharedGroupCache are threaded
        straight through to Resolve-IdentityInfo/Get-EffectiveGroupMembers;
        see their own comments for what each is for. Defaults reproduce
        exactly what the sequential path already did.
    #>
    param(
        [Parameter(Mandatory)][string]$ItemPath,
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)][string]$RootPath,
        $Cache = $script:IdentityCache,
        $GroupCache = $script:GroupMemberCache,
        $SharedLabelCache = $null,
        $SharedGroupCache = $null
    )

    $result = @{
        FolderRows = New-Object System.Collections.Generic.List[object]
        IdentityRows = New-Object System.Collections.Generic.List[object]
        InheritRow = $null
        Errors = New-Object System.Collections.Generic.List[object]
    }

    $acl = Get-ObjectAcl -ItemPath $ItemPath -IsDirectory $IsDirectory -ErrorCollector $result.Errors
    if (-not $acl) { return $result }

    $inheritanceBroken = $acl.AreAccessRulesProtected
    $owner = $null
    try {
        $owner = (Resolve-IdentityInfo -IdentityReference $acl.GetOwner([System.Security.Principal.NTAccount]) -Cache $Cache -SharedLabelCache $SharedLabelCache).Name
    }
    catch {
        try {
            $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            $result.Errors.Add(@{ ItemPath = $ItemPath; Message = "Could not determine owner (neither name nor SID resolved): $($_.Exception.Message)" })
            $owner = '(unresolved owner)'
        }
    }

    if ($inheritanceBroken -and $IsDirectory) {
        Write-Verbose "Inheritance is BROKEN at: $ItemPath"
        $result.InheritRow = [PSCustomObject]@{
            Path              = $ItemPath
            RootPath          = $RootPath
            Owner             = $owner
            InheritanceBroken = $true
        }
    }

    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    Write-Verbose "$ItemPath : $($rules.Count) ACE(s)"

    foreach ($ace in $rules) {

        if ($ace.IsInherited -and $IsDirectory -eq $false -and -not $IncludeInheritedFileAces) {
            continue
        }
        if ($ace.IsInherited -and $SkipInheritedAces) {
            continue
        }

        $idInfo = Resolve-IdentityInfo -IdentityReference $ace.IdentityReference -Cache $Cache -SharedLabelCache $SharedLabelCache
        $rightsInfo = Convert-RightsToFriendly -Rights $ace.FileSystemRights
        $applies = if ($IsDirectory) {
            Get-InheritanceDescription -InheritanceFlags $ace.InheritanceFlags -PropagationFlags $ace.PropagationFlags
        } else { 'This file' }

        $folderRow = [PSCustomObject]@{
            Path                 = $ItemPath
            RootPath             = $RootPath
            ObjectType           = if ($IsDirectory) { 'Folder' } else { 'File' }
            Owner                = $owner
            InheritanceBrokenHere = $inheritanceBroken
            IdentityName         = $idInfo.Name
            IdentitySid          = $idInfo.Sid
            IdentityType         = $idInfo.Type
            AccessControlType    = $ace.AccessControlType
            RightsSummary        = $rightsInfo.Summary
            RightsDetail         = $rightsInfo.Detail
            IsInheritedAce       = $ace.IsInherited
            AppliesTo            = $applies
        }
        $result.FolderRows.Add($folderRow)

        $result.IdentityRows.Add([PSCustomObject]@{
            IdentityName         = $idInfo.Name
            IdentitySid          = $idInfo.Sid
            IdentityType         = $idInfo.Type
            GrantedViaGroup      = ''
            Path                 = $ItemPath
            RootPath             = $RootPath
            ObjectType           = $folderRow.ObjectType
            AccessControlType    = $ace.AccessControlType
            RightsSummary        = $rightsInfo.Summary
            RightsDetail         = $rightsInfo.Detail
            IsInheritedAce       = $ace.IsInherited
            InheritanceBrokenHere = $inheritanceBroken
            AppliesTo            = $applies
        })

        if ($ExpandGroups -and $idInfo.Type -eq 'Group' -and ($idInfo.Name -notin $ExpandGroupsExclude) -and
            ($ExpandGroupsExclude -notcontains ($idInfo.Name -replace '^.*\\', ''))) {

            foreach ($member in (Get-EffectiveGroupMembers -IdentityInfo $idInfo -Cache $Cache -GroupCache $GroupCache -SharedLabelCache $SharedLabelCache -SharedGroupCache $SharedGroupCache)) {
                $result.IdentityRows.Add([PSCustomObject]@{
                    IdentityName         = $member.Name
                    IdentitySid          = $member.Sid
                    IdentityType         = $member.Type
                    GrantedViaGroup      = $idInfo.Name
                    Path                 = $ItemPath
                    RootPath             = $RootPath
                    ObjectType           = $folderRow.ObjectType
                    AccessControlType    = $ace.AccessControlType
                    RightsSummary        = $rightsInfo.Summary
                    RightsDetail         = $rightsInfo.Detail
                    IsInheritedAce       = $ace.IsInherited
                    InheritanceBrokenHere = $inheritanceBroken
                    AppliesTo            = $applies
                })
            }
        }
    }

    return $result
}

function Process-Object {
    <#
        Sequential-mode entry point: computes one object's rows via
        Get-ItemAuditRows (using the persistent, session-wide caches) and
        immediately appends them to the shared buffers/error log/flush cycle --
        behaviorally identical to how this function worked before
        -ThrottleLimit existed. On a -Resume run, skips anything already in
        $script:CompletedItemPaths (loaded from the checkpoint file) entirely --
        no ACL re-read, no processing -- and otherwise records this item's own
        completion for the checkpoint once its rows have been queued.
    #>
    param(
        [Parameter(Mandatory)][string]$ItemPath,
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)][string]$RootPath
    )

    if ($script:CompletedItemPaths.Contains($ItemPath)) {
        Write-Verbose "Skipping (already completed per checkpoint): $ItemPath"
        return
    }

    $rows = Get-ItemAuditRows -ItemPath $ItemPath -IsDirectory $IsDirectory -RootPath $RootPath
    foreach ($e in $rows.Errors) { Write-AuditError -ItemPath $e.ItemPath -Message $e.Message }
    if ($rows.InheritRow) { $script:InheritRows.Add($rows.InheritRow) }
    foreach ($r in $rows.FolderRows) { $script:FolderRows.Add($r) }
    foreach ($r in $rows.IdentityRows) { $script:IdentityRows.Add($r) }
    $script:PendingCompletedPaths.Add($ItemPath)
    Flush-Buffers
}

#endregion Core per-object processing --------------------------------------------

#region Tree walk (iterative, stack-based -- avoids recursion depth limits) -----

function Invoke-TreeWalk {
    param([Parameter(Mandatory)][string]$RootPath)

    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-AuditError -ItemPath $RootPath -Message 'Root path not found or inaccessible; skipping.'
        return
    }

    # Depth-first (default) uses a Stack (LIFO): push a folder's children, and the
    # most-recently-pushed child is visited next, so one branch is followed all
    # the way down before backing up to its siblings. Breadth-first uses a Queue
    # (FIFO) instead: children are visited in the order their PARENTS were
    # visited, so every folder at the current depth is processed before any
    # folder at the next depth. Both are O(1) per add/remove -- deliberately not
    # implemented as a single List with RemoveAt(0) for the breadth-first case,
    # which would be O(n) per removal and quietly quadratic on a large scan.
    if ($BreadthFirst) {
        $frontier = New-Object System.Collections.Generic.Queue[object]
    }
    else {
        $frontier = New-Object System.Collections.Generic.Stack[object]
    }
    if ($BreadthFirst) { $frontier.Enqueue(@{ Path = $RootPath; Depth = 0 }) }
    else { $frontier.Push(@{ Path = $RootPath; Depth = 0 }) }

    $processedCount = 0

    while ($frontier.Count -gt 0) {
        $current = if ($BreadthFirst) { $frontier.Dequeue() } else { $frontier.Pop() }
        $currentPath = $current.Path
        $currentDepth = $current.Depth

        Write-Verbose "Entering folder (depth $currentDepth): $currentPath"
        Process-Object -ItemPath $currentPath -IsDirectory $true -RootPath $RootPath
        $processedCount++
        if ($processedCount % 250 -eq 0) {
            Write-Progress -Activity "Scanning $RootPath" -Status "$processedCount objects processed (currently: $currentPath)"
        }

        if ($IncludeFiles) {
            $safePath = Get-LongPathSafe -InputPath $currentPath
            try {
                foreach ($filePath in [System.IO.Directory]::EnumerateFiles($safePath)) {
                    # Undo the \\?\ prefix for display/reporting purposes.
                    $displayPath = if ($currentPath.StartsWith('\\?\')) {
                        $filePath -replace '^\\\\\?\\UNC\\', '\\' -replace '^\\\\\?\\', ''
                    } else { $filePath }
                    Process-Object -ItemPath $displayPath -IsDirectory $false -RootPath $RootPath
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-AuditError -ItemPath $currentPath -Message 'Access denied enumerating files.'
            }
            catch {
                Write-AuditError -ItemPath $currentPath -Message "Failed enumerating files: $($_.Exception.Message)"
            }
        }

        if ($MaxDepth -ge 0 -and $currentDepth -ge $MaxDepth) {
            Write-Verbose "Not recursing below $currentPath (depth $currentDepth has reached MaxDepth=$MaxDepth$(if ($NoRecursion) { ' via -NoRecursion' }))"
            continue
        }

        $safePath = Get-LongPathSafe -InputPath $currentPath
        try {
            foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($safePath)) {
                $displaySub = if ($currentPath.StartsWith('\\?\')) {
                    $subDir -replace '^\\\\\?\\UNC\\', '\\' -replace '^\\\\\?\\', ''
                } else { $subDir }
                if ($BreadthFirst) { $frontier.Enqueue(@{ Path = $displaySub; Depth = $currentDepth + 1 }) }
                else { $frontier.Push(@{ Path = $displaySub; Depth = $currentDepth + 1 }) }
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-AuditError -ItemPath $currentPath -Message 'Access denied enumerating subfolders.'
        }
        catch {
            Write-AuditError -ItemPath $currentPath -Message "Failed enumerating subfolders: $($_.Exception.Message)"
        }
    }

    Write-Progress -Activity "Scanning $RootPath" -Completed
}

function Invoke-ParallelTreeWalk {
    <#
        Used only when -ThrottleLimit > 1 (always PS7+, enforced earlier).
        Deliberately a separate function from Invoke-TreeWalk rather than a
        branch inside it: keeps the default (-ThrottleLimit 1) path completely
        untouched by this file, at the cost of some duplicated discovery logic
        below -- an accepted trade-off in exchange for zero risk to the
        already-proven sequential path.

        Discovery (walking the tree to find what to scan) stays single-threaded
        and streams results into the pipeline as it goes, rather than
        collecting the whole tree into a list first -- keeps memory bounded on
        a very large tree and means parallel processing starts on the first
        few items almost immediately instead of a long silent pause. Only the
        expensive part -- reading each object's ACL and resolving its
        identities -- is dispatched to a pool of concurrent workers via
        ForEach-Object -Parallel. Each worker's function definitions are
        injected as TEXT captured from the real, already-defined functions (so
        they can never drift out of sync with what sequential mode runs), and
        results stream back to be appended to the shared row buffers / error
        log / flush cycle ONLY on this, the main thread -- workers never touch
        those directly, which is what avoids needing to make them thread-safe
        at all. See Get-ItemAuditRows and Resolve-IdentityInfo's own comments
        for the caching/thread-safety design this all depends on.
    #>
    param([Parameter(Mandatory)][string]$RootPath)

    if (-not (Test-Path -LiteralPath $RootPath)) {
        Write-AuditError -ItemPath $RootPath -Message 'Root path not found or inaccessible; skipping.'
        return
    }

    $funcNames = @('Get-LongPathSafe', 'Get-ObjectAcl', 'Resolve-IdentityInfo', 'Get-EffectiveGroupMembers',
                   'Convert-RightsToFriendly', 'Get-InheritanceDescription', 'Get-ItemAuditRows')
    $funcDefsText = ($funcNames | ForEach-Object { "function $_ {`n$(Get-Content "function:$_")`n}" }) -join "`n`n"

    function Get-DiscoveredItems {
        if ($BreadthFirst) { $frontier = New-Object System.Collections.Generic.Queue[object] }
        else { $frontier = New-Object System.Collections.Generic.Stack[object] }
        if ($BreadthFirst) { $frontier.Enqueue(@{ Path = $RootPath; Depth = 0 }) }
        else { $frontier.Push(@{ Path = $RootPath; Depth = 0 }) }

        while ($frontier.Count -gt 0) {
            $current = if ($BreadthFirst) { $frontier.Dequeue() } else { $frontier.Pop() }
            $currentPath = $current.Path
            $currentDepth = $current.Depth

            Write-Verbose "Entering folder (depth $currentDepth): $currentPath"
            Write-Output ([PSCustomObject]@{ Path = $currentPath; IsDirectory = $true; Depth = $currentDepth })

            if ($IncludeFiles) {
                $safePath = Get-LongPathSafe -InputPath $currentPath
                try {
                    foreach ($filePath in [System.IO.Directory]::EnumerateFiles($safePath)) {
                        $displayPath = if ($currentPath.StartsWith('\\?\')) {
                            $filePath -replace '^\\\\\?\\UNC\\', '\\' -replace '^\\\\\?\\', ''
                        } else { $filePath }
                        Write-Output ([PSCustomObject]@{ Path = $displayPath; IsDirectory = $false; Depth = $currentDepth })
                    }
                }
                catch [System.UnauthorizedAccessException] {
                    Write-AuditError -ItemPath $currentPath -Message 'Access denied enumerating files.'
                }
                catch {
                    Write-AuditError -ItemPath $currentPath -Message "Failed enumerating files: $($_.Exception.Message)"
                }
            }

            if ($MaxDepth -ge 0 -and $currentDepth -ge $MaxDepth) {
                Write-Verbose "Not recursing below $currentPath (depth $currentDepth has reached MaxDepth=$MaxDepth$(if ($NoRecursion) { ' via -NoRecursion' }))"
                continue
            }

            $safePath = Get-LongPathSafe -InputPath $currentPath
            try {
                foreach ($subDir in [System.IO.Directory]::EnumerateDirectories($safePath)) {
                    $displaySub = if ($currentPath.StartsWith('\\?\')) {
                        $subDir -replace '^\\\\\?\\UNC\\', '\\' -replace '^\\\\\?\\', ''
                    } else { $subDir }
                    if ($BreadthFirst) { $frontier.Enqueue(@{ Path = $displaySub; Depth = $currentDepth + 1 }) }
                    else { $frontier.Push(@{ Path = $displaySub; Depth = $currentDepth + 1 }) }
                }
            }
            catch [System.UnauthorizedAccessException] {
                Write-AuditError -ItemPath $currentPath -Message 'Access denied enumerating subfolders.'
            }
            catch {
                Write-AuditError -ItemPath $currentPath -Message "Failed enumerating subfolders: $($_.Exception.Message)"
            }
        }
    }

    $processedCount = 0
    $skippedCount = 0
    Get-DiscoveredItems | Where-Object {
        if ($script:CompletedItemPaths.Contains($_.Path)) {
            $skippedCount++
            Write-Verbose "Skipping (already completed per checkpoint): $($_.Path)"
            return $false
        }
        return $true
    } | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        . ([scriptblock]::Create($using:funcDefsText))

        # Redeclared bare/script-scoped variables the injected functions
        # reference: -ThrottleLimit always requires PS7+, so IsPSCore is always
        # true here regardless of what the main thread's edition happened to
        # be. adAvailable/ExpandGroups/etc. are the main script's own top-level
        # parameters, unqualified inside the injected function bodies -- PowerShell
        # resolves those through the calling scope chain, which is THIS
        # scriptblock's own scope, so setting same-named local variables here
        # (verified directly, not assumed) is what makes them visible.
        $script:IsPSCore = $true
        $adAvailable = $using:adAvailable
        $ExpandGroups = $using:ExpandGroups
        $ExpandGroupsExclude = $using:ExpandGroupsExclude
        $IncludeInheritedFileAces = $using:IncludeInheritedFileAces
        $SkipInheritedAces = $using:SkipInheritedAces
        if ($adAvailable) {
            try { $script:PrincipalCtx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain') }
            catch { $adAvailable = $false }
        }

        # Fresh, empty, per-item local caches -- ForEach-Object -Parallel gives
        # every item completely isolated scope with no persistence across
        # items even on a reused thread (verified directly, not assumed), so
        # there is no benefit to trying to keep these "warm" across items; all
        # of the real cross-worker caching benefit comes from the shared
        # ConcurrentDictionary caches passed in below.
        $rows = Get-ItemAuditRows -ItemPath $_.Path -IsDirectory $_.IsDirectory -RootPath $using:RootPath `
            -Cache @{} -GroupCache @{} `
            -SharedLabelCache $using:script:SharedLabelCache -SharedGroupCache $using:script:SharedGroupCache
        # The checkpoint needs to know which item this result belongs to, but
        # Get-ItemAuditRows's return value doesn't otherwise carry it -- the
        # aggregation step below only sees whatever streams back from here, not
        # the original pipeline object, so attach it before returning.
        $rows.ItemPath = $_.Path
        $rows
    } | ForEach-Object {
        $rows = $_
        foreach ($e in $rows.Errors) { Write-AuditError -ItemPath $e.ItemPath -Message $e.Message }
        if ($rows.InheritRow) { $script:InheritRows.Add($rows.InheritRow) }
        foreach ($r in $rows.FolderRows) { $script:FolderRows.Add($r) }
        foreach ($r in $rows.IdentityRows) { $script:IdentityRows.Add($r) }
        $script:PendingCompletedPaths.Add($rows.ItemPath)
        $processedCount++
        if ($processedCount % 250 -eq 0) {
            Write-Progress -Activity "Scanning $RootPath (parallel, -ThrottleLimit $ThrottleLimit)" -Status "$processedCount objects processed"
        }
        Flush-Buffers
    }
    if ($skippedCount -gt 0) {
        Write-Host "Skipped $skippedCount object(s) already completed in a previous run (per checkpoint)." -ForegroundColor Cyan
    }

    Write-Progress -Activity "Scanning $RootPath (parallel, -ThrottleLimit $ThrottleLimit)" -Completed
}

#endregion Tree walk --------------------------------------------------------------

#region Main ------------------------------------------------------------------

Write-Host "NTFS Permission Audit v$ScriptVersion starting. Output folder: $OutputFolder" -ForegroundColor Cyan
if ($ThrottleLimit -gt 1) {
    Write-Host "Parallel processing enabled: -ThrottleLimit $ThrottleLimit" -ForegroundColor Cyan
}
foreach ($root in $Path) {
    Write-Host "Scanning root: $root" -ForegroundColor Cyan
    if ($ThrottleLimit -gt 1) { Invoke-ParallelTreeWalk -RootPath $root }
    else { Invoke-TreeWalk -RootPath $root }
}

Flush-Buffers -Force

if ($ThrottleLimit -gt 1 -or $Resume) {
    # Two distinct reasons $script:IdentityCache can be missing identities
    # that legitimately belong in ADIdentityDetails.csv, both fixed the same
    # way (re-resolve properly on the main thread, once, at the end):
    #
    # 1. Under parallel processing, every worker resolves identities into its
    #    own fresh, throwaway per-item cache -- never into $script:IdentityCache
    #    itself -- and the SHARED cache deliberately holds only plain Name/Type
    #    labels, never a live .Principal object (see Resolve-IdentityInfo's own
    #    comment for why).
    # 2. Under -Resume, this is a brand-new process: $script:IdentityCache only
    #    ever contains identities THIS invocation actually processed. Anything
    #    that only ever appeared in the already-checkpointed (skipped) portion
    #    of the scan -- fully valid rows already sitting in
    #    IdentityPermissions.csv from before this invocation even started --
    #    never touches this process's IdentityCache OR SharedLabelCache at all,
    #    since those items are never re-processed by design. Confirmed as a
    #    real gap (not just theoretical) with a dedicated reproduction before
    #    being fixed here.
    #
    # Left unfixed, ADIdentityDetails.csv would silently omit real identities
    # that DO have rows in IdentityPermissions.csv -- not a crash, just a
    # quiet gap that undermines exactly the completeness -Resume is supposed
    # to guarantee.
    $sidsToBackfill = New-Object System.Collections.Generic.HashSet[string]
    if ($ThrottleLimit -gt 1) {
        foreach ($sidStr in $script:SharedLabelCache.Keys) { [void]$sidsToBackfill.Add($sidStr) }
    }
    if ($Resume -and (Test-Path -LiteralPath $IdentityReportPath)) {
        Write-Verbose "Reading back $IdentityReportPath to find identities from the already-completed (checkpointed) portion of a resumed scan, which this process never touched directly."
        Import-Csv -LiteralPath $IdentityReportPath | ForEach-Object {
            if ($_.IdentitySid) { [void]$sidsToBackfill.Add($_.IdentitySid) }
        }
    }
    Write-Verbose "Re-resolving $($sidsToBackfill.Count) identity(ies) to ensure ADIdentityDetails.csv covers everyone actually referenced in IdentityPermissions.csv."
    foreach ($sidStr in $sidsToBackfill) {
        if (-not $script:IdentityCache.ContainsKey($sidStr)) {
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
                Resolve-IdentityInfo -IdentityReference $sidObj | Out-Null
            }
            catch {
                Write-AuditError -ItemPath "Identity:$sidStr" -Message "Failed to re-resolve for ADIdentityDetails.csv: $($_.Exception.Message)"
            }
        }
    }
}

Write-Verbose "Building AD identity details for $($script:IdentityCache.Count) unique identity(ies) encountered during the scan."
$script:IdentityCache.Values |
    Sort-Object Type, Name -ErrorAction SilentlyContinue |
    ForEach-Object { Get-AdIdentityDetailRow -IdentityInfo $_ } |
    Export-Csv -LiteralPath $IdentityDetailsPath -NoTypeInformation -Append:$Resume

# A finished run gets a Completed marker specifically so a LATER -Resume
# attempt can tell "nothing left to do here" apart from "this one crashed too"
# -- see the -Resume parameter's own help for the full checkpoint/resume design.
New-Item -ItemType File -Path $CompletedMarkerPath -Force | Out-Null

Write-Host "Done." -ForegroundColor Green
Write-Host "  Per-folder view       : $FolderReportPath"
Write-Host "  Per-identity view     : $IdentityReportPath"
Write-Host "  AD identity details   : $IdentityDetailsPath"
Write-Host "  Inheritance exceptions: $InheritanceExceptions"
if (Test-Path -LiteralPath $ErrorLogPath) {
    Write-Host "  Errors were logged to : $ErrorLogPath" -ForegroundColor Yellow
}

#endregion Main
