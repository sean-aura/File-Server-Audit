#Requires -Version 5.1
# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    "Interrogates" the file server(s)/namespace first: enumerates SMB shares and
    share-level permissions where possible, and resolves DFS namespace paths to their
    physical backing target(s) -- without requiring DFS management access or the
    DFSN RSAT module.

.DESCRIPTION
    Run this BEFORE Invoke-NTFSPermissionAudit.ps1 to work out the physical paths to
    feed it. Every capability here is independently optional and degrades gracefully
    if the relevant module/rights/connectivity isn't present on whatever machine you
    end up running this from -- nothing hard-fails the whole script.

    Two different ways to learn a DFS path's physical target are supported:

      1. -DfsPath (recommended when you don't manage DFS): resolves one or more
         *already-known* DFS paths (e.g. '\\contoso.com\Public\Finance' -- the path
         people actually use) to their backing server+share, using the Win32
         NetDfsGetClientInfo API. This is exactly the client-side referral lookup
         Windows itself performs the moment you open that path in Explorer -- it
         needs no DFS management/admin rights, no RSAT tools, nothing beyond
         ordinary read access to browse the namespace. For an active/standby pair
         it also tells you which target is the one currently Active (the one a
         client would actually use right now), not just which are Online.

      2. -DfsNamespace (bonus, only if you happen to have it): if the DFSN RSAT
         module is present AND your account has rights to read the namespace
         configuration, this walks the *entire* namespace tree (Get-DfsnFolder /
         Get-DfsnFolderTarget) to discover every folder, not just ones you already
         know about. This is a strictly higher permission tier than -DfsPath --
         if you don't have DFS config access, this option simply won't apply to
         you, and the script says so rather than failing confusingly.

    You can use either, both, or neither (if you already know the physical paths,
    skip this script entirely).

.PARAMETER ComputerName
    Optional. One or more file servers to query for local SMB shares (e.g. the
    active and standby nodes), using the in-box SmbShare module. Requires
    WinRM/CIM connectivity to the target and that the SmbShare cmdlets exist there
    (they ship in-box on Windows Server and modern Windows client, but the machine
    *running this script* also needs the SmbShare module locally to call them --
    checked automatically, with a clear warning and graceful skip if missing).

.PARAMETER DfsPath
    Optional. One or more specific DFS namespace paths (root or subfolder) whose
    physical target(s) you want resolved, e.g. '\\contoso.com\Public\Finance'.
    Uses the client-side NetDfsGetClientInfo API -- no DFS management rights or
    RSAT module required, just the ability to browse the path.

.PARAMETER DfsNamespace
    Optional. Root DFS namespace path, e.g. '\\contoso.com\Public'. If supplied
    AND the DFSN module is available AND your account can read the namespace
    config, walks the whole namespace tree to discover every folder + target.
    If the module/rights aren't there, this is skipped with an explanatory
    warning rather than failing the script -- use -DfsPath instead in that case.

.PARAMETER NoRecursion
    Only affects -DfsNamespace (full tree enumeration mode). DFS folders can
    themselves contain nested DFS folders; by default the whole tree is walked.
    -NoRecursion limits discovery to the namespace's immediate top-level folders.
    Has no effect on -DfsPath (each path you give is resolved individually,
    there's no "tree" to recurse) or on share enumeration (always a flat list).

.PARAMETER OutputFolder
    Where the CSV output is written. Defaults to a timestamped folder in the
    current directory.

.EXAMPLE
    .\Get-FileServerShareInventory.ps1 -DfsPath '\\contoso.com\Public\Finance','\\contoso.com\Public\HR'

    The scenario where you don't manage DFS and aren't sure what's installed:
    resolves just those two known paths to their physical server/share and
    active/standby state, no admin rights or extra modules needed.

.EXAMPLE
    .\Get-FileServerShareInventory.ps1 -ComputerName FS01,FS02 -DfsNamespace '\\contoso.com\Public'

    The fuller scenario, if you do have both server access and DFS config rights:
    enumerates shares on both nodes and walks the whole namespace tree.

.NOTES
    Version: 0.1.0

    Minimum PowerShell 5.1. If you already know the physical paths you care about,
    you can skip this script entirely and pass them straight to
    Invoke-NTFSPermissionAudit.ps1 -- and note that Invoke-NTFSPermissionAudit.ps1
    can also be pointed directly at a DFS namespace path; Windows resolves the
    referral transparently at the file-system level, so this discovery script is
    purely optional, informational tooling, never a hard prerequisite.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,

    [string[]]$DfsPath,

    [string]$DfsNamespace,

    [switch]$NoRecursion,

    [string]$OutputFolder = ".\ShareInventory_$(Get-Date -Format yyyyMMdd_HHmmss)"
)

$ScriptVersion = '0.1.0'

$ErrorActionPreference = 'Stop'

if (-not $ComputerName -and -not $DfsPath -and -not $DfsNamespace) {
    throw "Specify at least one of -ComputerName, -DfsPath, or -DfsNamespace. See Get-Help .\Get-FileServerShareInventory.ps1 -Full for the difference between -DfsPath (no special access needed) and -DfsNamespace (needs DFS config read rights + the DFSN module)."
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
$OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath
$SharesCsv = Join-Path $OutputFolder 'Shares.csv'
$DfsCsv    = Join-Path $OutputFolder 'DfsMapping.csv'

Write-Host "File Server Share Inventory v$ScriptVersion. Output folder: $OutputFolder" -ForegroundColor Cyan

$dfsRows = New-Object System.Collections.Generic.List[object]

#region DFS client-side referral resolution (no admin/RSAT required) -----------

function Add-DfsInteropType {
    # Defines the P/Invoke signatures for NetDfsGetClientInfo once per session.
    # This is the same Win32 API Windows itself calls when you open a DFS path --
    # a client-side referral lookup, not a DFS management/config read -- so it
    # works without RSAT and without any special rights beyond browsing the path.
    if (-not ('Toolkit.DfsNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Toolkit
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DFS_STORAGE_INFO
    {
        public int State;
        [MarshalAs(UnmanagedType.LPWStr)] public string ServerName;
        [MarshalAs(UnmanagedType.LPWStr)] public string ShareName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct DFS_INFO_3
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string EntryPath;
        public int State;
        public int NumberOfStorages;
        public IntPtr Storage;
    }

    public static class DfsNative
    {
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetDfsGetClientInfo(
            string DfsEntryPath,
            string ServerName,
            string ShareName,
            int Level,
            out IntPtr Buffer);

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);
    }
}
'@ -ErrorAction Stop
    }
}

function Resolve-DfsClientTarget {
    <#
        Resolves one DFS path (namespace root or any subfolder) to its backing
        physical storage target(s): server, share, and whether each is currently
        Online and/or the Active target a client would actually use right now --
        exactly what you want for telling apart the active vs. standby node.
    #>
    param([Parameter(Mandatory)][string]$Path)

    Add-DfsInteropType
    Write-Verbose "Resolving DFS client referral for: $Path"

    $bufferPtr = [IntPtr]::Zero
    $results = New-Object System.Collections.Generic.List[object]
    try {
        $ret = [Toolkit.DfsNative]::NetDfsGetClientInfo($Path, $null, $null, 3, [ref]$bufferPtr)
        if ($ret -ne 0) {
            Write-Warning "Could not resolve '$Path' via DFS client referral (Win32 error $ret). It may not be a DFS path, the DFS client may not have a referral cached for it yet, or it's unreachable. Try browsing to the path once first, or double-check it's actually a DFS namespace path."
            return @()
        }
        if ($bufferPtr -eq [IntPtr]::Zero) { return @() }

        $info3 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bufferPtr, [type]'Toolkit.DFS_INFO_3')

        if ($info3.NumberOfStorages -gt 0 -and $info3.Storage -ne [IntPtr]::Zero) {
            $itemSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]'Toolkit.DFS_STORAGE_INFO')
            for ($i = 0; $i -lt $info3.NumberOfStorages; $i++) {
                $itemPtr = [IntPtr]::Add($info3.Storage, ($i * $itemSize))
                $storage = [System.Runtime.InteropServices.Marshal]::PtrToStructure($itemPtr, [type]'Toolkit.DFS_STORAGE_INFO')

                # DFS_STORAGE_STATE_OFFLINE=1, DFS_STORAGE_STATE_ONLINE=2, DFS_STORAGE_STATE_ACTIVE=4 (bit flags)
                $isOnline = ($storage.State -band 0x2) -ne 0
                $isActive = ($storage.State -band 0x4) -ne 0

                $results.Add([PSCustomObject]@{
                    DfsPath         = $Path
                    TargetServer    = $storage.ServerName
                    TargetShareName = $storage.ShareName
                    TargetPath      = "\\$($storage.ServerName)\$($storage.ShareName)"
                    IsOnline        = $isOnline
                    IsActiveTarget  = $isActive
                    RawState        = $storage.State
                    ResolvedVia     = 'ClientReferral (NetDfsGetClientInfo)'
                })
            }
        }
    }
    catch {
        Write-Warning "DFS client referral resolution failed for '$Path': $($_.Exception.Message)"
    }
    finally {
        if ($bufferPtr -ne [IntPtr]::Zero) {
            [Toolkit.DfsNative]::NetApiBufferFree($bufferPtr) | Out-Null
        }
    }
    return $results.ToArray()
}

if ($DfsPath) {
    Write-Host "Resolving $($DfsPath.Count) DFS path(s) via client-side referral (no DFS admin rights needed)..." -ForegroundColor Cyan
    foreach ($p in $DfsPath) {
        $targets = Resolve-DfsClientTarget -Path $p
        if ($targets.Count -eq 0) {
            Write-Warning "No targets resolved for '$p' -- see warning above. It will not appear in DfsMapping.csv."
        }
        foreach ($t in $targets) { $dfsRows.Add($t) }
    }
}

#endregion DFS client-side referral resolution ---------------------------------

#region Share enumeration (optional, SmbShare module + connectivity permitting) -

$shareRows = New-Object System.Collections.Generic.List[object]
# Default/administrative shares that are noise for this kind of audit.
$excludedShares = @('ADMIN$', 'IPC$', 'print$', 'NETLOGON', 'SYSVOL') + (0..25 | ForEach-Object { "$([char](65+$_))$" })

if ($ComputerName) {
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        Write-Warning "The SmbShare module (Get-SmbShare/Get-SmbShareAccess) isn't available on this machine, so share enumeration is being skipped. This doesn't block anything else in this script or the NTFS audit -- it just means Shares.csv won't be produced. If you can, run this from the file server itself or a machine with the SmbShare module, or ask whoever manages the servers for the share list."
    }
    else {
        foreach ($computer in $ComputerName) {
            Write-Host "Querying shares on $computer..." -ForegroundColor Cyan
            try {
                $cimSession = New-CimSession -ComputerName $computer -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not open a CIM session to $computer : $($_.Exception.Message). Skipping this computer."
                continue
            }

            try {
                $shares = Get-SmbShare -CimSession $cimSession | Where-Object {
                    -not $_.Special -and ($excludedShares -notcontains $_.Name)
                }
                Write-Verbose "$computer : found $($shares.Count) non-default share(s)"

                foreach ($share in $shares) {
                    Write-Verbose "$computer : reading share-level ACL for '$($share.Name)' ($($share.Path))"
                    $shareAccess = $null
                    try {
                        $shareAccess = Get-SmbShareAccess -CimSession $cimSession -Name $share.Name |
                            ForEach-Object { "$($_.AccountName):$($_.AccessControlType)/$($_.AccessRight)" }
                        $shareAccess = $shareAccess -join '; '
                    }
                    catch {
                        Write-Warning "Could not read share-level ACL for \\$computer\$($share.Name): $($_.Exception.Message)"
                    }

                    $shareRows.Add([PSCustomObject]@{
                        ComputerName          = $computer
                        ShareName             = $share.Name
                        PhysicalPath          = "\\$computer\$($share.Name)"
                        LocalPath             = $share.Path
                        Description           = $share.Description
                        ShareLevelAccess      = $shareAccess
                        ContinuouslyAvailable = $share.ContinuouslyAvailable
                        EncryptData           = $share.EncryptData
                    })
                }
            }
            catch {
                Write-Warning "Failed enumerating shares on $computer : $($_.Exception.Message)"
            }
            finally {
                Remove-CimSession -CimSession $cimSession
            }
        }

        $shareRows | Sort-Object ComputerName, ShareName | Export-Csv -LiteralPath $SharesCsv -NoTypeInformation
        Write-Host "Share inventory written to $SharesCsv ($($shareRows.Count) shares)." -ForegroundColor Green
    }
}

#endregion Share enumeration ----------------------------------------------------

#region Full namespace enumeration (optional bonus, needs DFSN module + rights) -

if ($DfsNamespace) {
    Write-Host "Attempting full DFS namespace enumeration for $DfsNamespace (requires the DFSN module and DFS config read rights)..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name DFSN)) {
        Write-Warning "DFSN module not available on this machine, so full namespace enumeration is being skipped. This is a separate, higher-privilege capability than -DfsPath (which still works without it) -- use -DfsPath with the specific paths you already know instead, or install the 'DFS Namespaces Tools' feature (RSAT-DFS-Mgmt-Con) / run this on a namespace server if you later get access to do so."
    }
    else {
        try {
            Import-Module DFSN -ErrorAction Stop

            # DFS folders can themselves contain nested DFS folders (e.g. \Public\Finance\Archive
            # as its own linked folder under \Public\Finance). Get-DfsnFolder -Path 'X\*' only
            # returns X's immediate children, so walk the tree breadth-first to find the rest,
            # unless -NoRecursion says to stop at the top level.
            $folders = New-Object System.Collections.Generic.List[object]
            $queue = New-Object System.Collections.Generic.Queue[string]
            $queue.Enqueue($DfsNamespace)

            while ($queue.Count -gt 0) {
                $currentNamespacePath = $queue.Dequeue()
                Write-Verbose "Enumerating DFS folders under: $currentNamespacePath"
                try {
                    $children = Get-DfsnFolder -Path "$currentNamespacePath\*"
                }
                catch {
                    Write-Warning "Failed to enumerate DFS folders under $currentNamespacePath (likely an access-rights issue reading namespace config): $($_.Exception.Message)"
                    continue
                }

                foreach ($child in $children) {
                    $folders.Add($child)
                    if (-not $NoRecursion) {
                        $queue.Enqueue($child.Path)
                    }
                }
            }
            Write-Verbose "Discovered $($folders.Count) DFS folder(s) total$(if ($NoRecursion) { ' (top level only, -NoRecursion)' })."

            foreach ($folder in $folders) {
                try {
                    $targets = Get-DfsnFolderTarget -Path $folder.Path
                }
                catch {
                    Write-Warning "Failed to enumerate targets for $($folder.Path): $($_.Exception.Message)"
                    continue
                }
                Write-Verbose "$($folder.Path) : $($targets.Count) target(s)"

                foreach ($target in $targets) {
                    $targetServer = $null
                    $targetShare  = $null
                    if ($target.TargetPath -match '^\\\\([^\\]+)\\([^\\]+)') {
                        $targetServer = $Matches[1]
                        $targetShare  = $Matches[2]
                    }

                    $dfsRows.Add([PSCustomObject]@{
                        DfsPath         = $folder.Path
                        TargetServer    = $targetServer
                        TargetShareName = $targetShare
                        TargetPath      = $target.TargetPath
                        IsOnline        = ($target.State -eq 'Online')
                        IsActiveTarget  = $null   # not exposed by Get-DfsnFolderTarget; use -DfsPath if you need this
                        RawState        = $target.State
                        ResolvedVia     = 'NamespaceEnum (Get-DfsnFolderTarget)'
                    })
                }
            }
        }
        catch {
            Write-Warning "Full DFS namespace enumeration failed: $($_.Exception.Message). Falling back to whatever -DfsPath results (if any) were already resolved above."
        }
    }
}

#endregion Full namespace enumeration -------------------------------------------

if ($dfsRows.Count -gt 0) {
    $dfsRows | Sort-Object DfsPath, TargetServer | Export-Csv -LiteralPath $DfsCsv -NoTypeInformation
    Write-Host "DFS mapping written to $DfsCsv ($($dfsRows.Count) row(s))." -ForegroundColor Green
    Write-Host "Use the TargetPath column as -Path input to Invoke-NTFSPermissionAudit.ps1 -- or just point it at the DFS path itself; Windows resolves the referral transparently either way." -ForegroundColor Yellow
}
else {
    Write-Host "No DFS mapping produced (no -DfsPath / -DfsNamespace given, or nothing resolved)." -ForegroundColor Yellow
    if ($shareRows.Count -gt 0) {
        Write-Host "Use the PhysicalPath column in Shares.csv as -Path input to Invoke-NTFSPermissionAudit.ps1." -ForegroundColor Yellow
    }
}
