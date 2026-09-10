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

.PARAMETER SkipInheritedAcesInFolderReport
    Omit purely-inherited ACEs from FolderPermissions.csv (keep only explicit ACEs
    and the folder's own inheritance-broken flag). Useful to cut noise once you've
    confirmed the ACL at the top of a share and only want to see where it changes.

.PARAMETER OutputFolder
    Where the CSV/log files are written. Created if it doesn't exist. Defaults to
    a timestamped folder in the current directory.

.PARAMETER NoAdLookup
    Skip AD identity-type resolution and group expansion entirely (fastest option,
    e.g. for a quick first pass or when not running with domain connectivity).
    Identities are still shown by their resolved NTAccount name/SID. ADIdentityDetails.csv
    is still produced but every row will just show Name/Sid/Type with a note that AD
    lookup was disabled, since none of the HR/account-state fields can be populated.

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -ExpandGroups

    Full folder-only audit of the Finance share, expanding group membership.

.EXAMPLE
    .\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance','\\FS01\Shared\HR' `
        -IncludeFiles -MaxDepth 3 -OutputFolder C:\Audit\Run1

.NOTES
    Version: 0.1.0

    Minimum PowerShell 5.1. Run interactively as (or "runas" / scheduled task under) an
    account with at least Read + Read-Permissions NTFS access to every object being
    scanned, and read access to Active Directory for identity resolution. No RSAT
    ActiveDirectory module is required; System.DirectoryServices.AccountManagement
    (part of the .NET Framework) is used instead.

    ADIdentityDetails.csv's "last logon" column reads the replicated lastLogonTimestamp
    attribute (not the single-DC-only lastLogon attribute), which by design can lag the
    true last logon by up to ~14 days (the default domain replication interval for that
    attribute) - treat it as "roughly this recently", not to-the-day precise, when using
    it to spot dormant accounts.

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

    [switch]$ExpandGroups,

    [string[]]$ExpandGroupsExclude = @('Domain Users', 'Everyone', 'Authenticated Users', 'Users', 'BUILTIN\Users'),

    [switch]$SkipInheritedAcesInFolderReport,

    [string]$OutputFolder = ".\NTFSAudit_$(Get-Date -Format yyyyMMdd_HHmmss)",

    [switch]$NoAdLookup
)

#region Setup ---------------------------------------------------------------

$ScriptVersion = '0.1.0'

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($NoRecursion) {
    if ($PSBoundParameters.ContainsKey('MaxDepth') -and $MaxDepth -ne 0) {
        Write-Warning "-NoRecursion was specified along with -MaxDepth $MaxDepth; -NoRecursion takes precedence (each root will be scanned at depth 0 only)."
    }
    $MaxDepth = 0
}
Write-Verbose "Effective settings: MaxDepth=$MaxDepth  IncludeFiles=$IncludeFiles  IncludeInheritedFileAces=$IncludeInheritedFileAces  ExpandGroups=$ExpandGroups  NoAdLookup=$NoAdLookup"

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath

$FolderReportPath      = Join-Path $OutputFolder 'FolderPermissions.csv'
$IdentityReportPath    = Join-Path $OutputFolder 'IdentityPermissions.csv'
$InheritanceExceptions = Join-Path $OutputFolder 'InheritanceExceptions.csv'
$IdentityDetailsPath   = Join-Path $OutputFolder 'ADIdentityDetails.csv'
$ErrorLogPath          = Join-Path $OutputFolder 'Errors.log'

# Wipe any prior run's files so CSVs aren't silently appended to stale data.
foreach ($f in @($FolderReportPath, $IdentityReportPath, $InheritanceExceptions, $IdentityDetailsPath, $ErrorLogPath)) {
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
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
    #>
    param([Parameter(Mandatory)]$IdentityReference)

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
    if ($script:IdentityCache.ContainsKey($sidStr)) {
        Write-Verbose "Identity cache hit: $sidStr"
        return $script:IdentityCache[$sidStr]
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
    $script:IdentityCache[$sidStr] = $result
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
    #>
    param([Parameter(Mandatory)]$IdentityInfo)

    if ($IdentityInfo.Type -ne 'Group' -or -not $IdentityInfo.Principal) { return @() }

    $sidStr = $IdentityInfo.Sid
    if ($script:GroupMemberCache.ContainsKey($sidStr)) {
        Write-Verbose "Group member cache hit: $($IdentityInfo.Name)"
        return $script:GroupMemberCache[$sidStr]
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
            if ($script:IdentityCache.ContainsKey($memberSidStr)) {
                $cached = $script:IdentityCache[$memberSidStr]
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
                $script:IdentityCache[$memberSidStr] = $cached
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
    $script:GroupMemberCache[$sidStr] = $result
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
        Wraps [System.IO.Directory]::GetAccessControl / File equivalent with the
        long-path fallback, returning $null (and logging) on failure rather than
        throwing, so a single bad object never aborts the whole tree walk.
    #>
    param([Parameter(Mandatory)][string]$ItemPath, [Parameter(Mandatory)][bool]$IsDirectory)

    $safePath = Get-LongPathSafe -InputPath $ItemPath
    Write-Verbose "Reading ACL: $ItemPath"
    try {
        if ($IsDirectory) {
            return [System.IO.Directory]::GetAccessControl($safePath)
        }
        else {
            return [System.IO.File]::GetAccessControl($safePath)
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-AuditError -ItemPath $ItemPath -Message 'Access denied reading ACL.'
    }
    catch {
        Write-AuditError -ItemPath $ItemPath -Message "Failed reading ACL: $($_.Exception.Message)"
    }
    return $null
}

#endregion Helper functions ----------------------------------------------------

#region Core per-object processing ---------------------------------------------

# Buffers, flushed to CSV in batches to keep memory bounded on large trees.
$script:FolderRows   = New-Object System.Collections.Generic.List[object]
$script:IdentityRows = New-Object System.Collections.Generic.List[object]
$script:InheritRows  = New-Object System.Collections.Generic.List[object]
$script:FlushEvery    = 2000
$script:FolderHeaderWritten   = $false
$script:IdentityHeaderWritten = $false
$script:InheritHeaderWritten  = $false

function Flush-Buffers {
    param([switch]$Force)

    if ($Force -or $script:FolderRows.Count -ge $script:FlushEvery) {
        if ($script:FolderRows.Count -gt 0) {
            Write-Verbose "Flushing $($script:FolderRows.Count) row(s) to $FolderReportPath"
            $script:FolderRows | Export-Csv -LiteralPath $FolderReportPath -NoTypeInformation -Append:$script:FolderHeaderWritten
            $script:FolderHeaderWritten = $true
            $script:FolderRows.Clear()
        }
    }
    if ($Force -or $script:IdentityRows.Count -ge $script:FlushEvery) {
        if ($script:IdentityRows.Count -gt 0) {
            $script:IdentityRows | Export-Csv -LiteralPath $IdentityReportPath -NoTypeInformation -Append:$script:IdentityHeaderWritten
            $script:IdentityHeaderWritten = $true
            $script:IdentityRows.Clear()
        }
    }
    if ($Force -or $script:InheritRows.Count -ge $script:FlushEvery) {
        if ($script:InheritRows.Count -gt 0) {
            $script:InheritRows | Export-Csv -LiteralPath $InheritanceExceptions -NoTypeInformation -Append:$script:InheritHeaderWritten
            $script:InheritHeaderWritten = $true
            $script:InheritRows.Clear()
        }
    }
}

function Process-Object {
    <#
        Captures ACL info for a single file-system object (folder or file) and
        appends rows to the folder-view and identity-view buffers.
    #>
    param(
        [Parameter(Mandatory)][string]$ItemPath,
        [Parameter(Mandatory)][bool]$IsDirectory,
        [Parameter(Mandatory)][string]$RootPath
    )

    $acl = Get-ObjectAcl -ItemPath $ItemPath -IsDirectory $IsDirectory
    if (-not $acl) { return }

    $inheritanceBroken = $acl.AreAccessRulesProtected
    $owner = $null
    try { $owner = (Resolve-IdentityInfo -IdentityReference $acl.GetOwner([System.Security.Principal.NTAccount])).Name } catch { $owner = $acl.Owner }

    if ($inheritanceBroken -and $IsDirectory) {
        Write-Verbose "Inheritance is BROKEN at: $ItemPath"
        $script:InheritRows.Add([PSCustomObject]@{
            Path              = $ItemPath
            RootPath          = $RootPath
            Owner             = $owner
            InheritanceBroken = $true
        })
    }

    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    Write-Verbose "$ItemPath : $($rules.Count) ACE(s)"

    foreach ($ace in $rules) {

        if ($ace.IsInherited -and $IsDirectory -eq $false -and -not $IncludeInheritedFileAces) {
            continue
        }
        if ($ace.IsInherited -and $SkipInheritedAcesInFolderReport) {
            # Still needed for identity view unless caller truly wants it gone;
            # honour the switch literally: skip everywhere it's set.
            continue
        }

        $idInfo = Resolve-IdentityInfo -IdentityReference $ace.IdentityReference
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
        $script:FolderRows.Add($folderRow)

        $script:IdentityRows.Add([PSCustomObject]@{
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

            foreach ($member in (Get-EffectiveGroupMembers -IdentityInfo $idInfo)) {
                $script:IdentityRows.Add([PSCustomObject]@{
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

    # Stack entries: @{ Path = ...; Depth = ... }
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@{ Path = $RootPath; Depth = 0 })

    $processedCount = 0

    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
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
                $stack.Push(@{ Path = $displaySub; Depth = $currentDepth + 1 })
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

#endregion Tree walk --------------------------------------------------------------

#region Main ------------------------------------------------------------------

Write-Host "NTFS Permission Audit v$ScriptVersion starting. Output folder: $OutputFolder" -ForegroundColor Cyan
foreach ($root in $Path) {
    Write-Host "Scanning root: $root" -ForegroundColor Cyan
    Invoke-TreeWalk -RootPath $root
}

Flush-Buffers -Force

Write-Verbose "Building AD identity details for $($script:IdentityCache.Count) unique identity(ies) encountered during the scan."
$script:IdentityCache.Values |
    Sort-Object Type, Name -ErrorAction SilentlyContinue |
    ForEach-Object { Get-AdIdentityDetailRow -IdentityInfo $_ } |
    Export-Csv -LiteralPath $IdentityDetailsPath -NoTypeInformation

Write-Host "Done." -ForegroundColor Green
Write-Host "  Per-folder view       : $FolderReportPath"
Write-Host "  Per-identity view     : $IdentityReportPath"
Write-Host "  AD identity details   : $IdentityDetailsPath"
Write-Host "  Inheritance exceptions: $InheritanceExceptions"
if (Test-Path -LiteralPath $ErrorLogPath) {
    Write-Host "  Errors were logged to : $ErrorLogPath" -ForegroundColor Yellow
}

#endregion Main
