# File Server Permission Audit Toolkit

Three scripts for auditing NTFS/share permissions on a DFS-fronted Windows
file server pair (one active node, one standby), plus a self-contained
interactive HTML report. PowerShell 5.1 compatible.

Licensed under the MIT License -- see [LICENSE](LICENSE).

**Nothing here requires DFS management access or a specific set of installed
modules.** Every capability that depends on an optional module or elevated
rights (SmbShare cmdlets, the DFSN RSAT module, AD lookup) is individually
guarded and degrades gracefully with a clear message if it isn't available --
the scripts never hard-fail just because one optional piece is missing.

## Workflow

```
1. Get-FileServerShareInventory.ps1   -- OPTIONAL "interrogate" step
        |
        v
   Shares.csv        (share name, physical path, share-level ACL -- if SmbShare available)
   DfsMapping.csv    (DFS path -> physical target -> active/standby state)
        |
        v
2. Invoke-NTFSPermissionAudit.ps1     -- walk the paths, capture ACLs
        |
        v
   FolderPermissions.csv       (per-folder-tree view)
   IdentityPermissions.csv     (per-user/identity view)
   ADIdentityDetails.csv       (who these identities actually are, per AD)
   InheritanceExceptions.csv   (every folder where inheritance is broken)
   Errors.log                  (access-denied / path-too-long, etc.)
        |
        v
3. Build-AccessMapHtml.ps1            -- OPTIONAL: turn the CSVs into one
        |                                 interactive HTML file
        v
   AccessMap.html   -- open directly in a browser, no server required
```

Step 1 is genuinely optional. **`Invoke-NTFSPermissionAudit.ps1` can be pointed
directly at a DFS namespace path** (e.g. `\\contoso.com\Public\Finance`) --
Windows resolves the referral transparently at the file-system level, so the
audit script needs no DFS awareness at all. Use step 1 only if you also want
to *record* which physical server is currently backing that path (useful for
an active/standby setup), or if you don't already know the paths you care
about.

### Step 1 (optional) - discover shares and/or resolve DFS targets

You do **not** need DFS management access or the DFSN module for the most
useful part of this: resolving a DFS path you already know (e.g. one people
actually use day to day) to its physical target and telling active from
standby:

```powershell
.\Get-FileServerShareInventory.ps1 -DfsPath '\\contoso.com\Public\Finance','\\contoso.com\Public\HR'
```

This uses the same client-side DFS referral lookup Windows performs the
moment you open that path in Explorer (the `NetDfsGetClientInfo` API) -- no
admin rights on the DFS namespace, no RSAT tools, just ordinary read access
to browse the path. Output (`DfsMapping.csv`) includes `IsOnline` and
`IsActiveTarget` per target, so for your active/standby pair you can see
which node the client would actually use right now.

If you *do* separately have server access and want the full share list
(including share-level ACLs, a distinct layer from NTFS permissions):

```powershell
.\Get-FileServerShareInventory.ps1 -ComputerName FS01,FS02 -DfsPath '\\contoso.com\Public\Finance'
```

And if you happen to *also* have DFS config read rights and the DFSN module
installed, `-DfsNamespace '\\contoso.com\Public'` will walk the **entire**
namespace tree to discover folders you don't already know about -- this is a
strictly higher-privilege operation than `-DfsPath`, so if you don't have
that access, just leave it out; `-DfsPath` still gives you everything you
need for paths you already know.

If none of the above applies to you (no server access, no DFS access, module
availability unknown), skip this script entirely -- point step 2 straight at
whatever paths you already know (physical or DFS, doesn't matter).

### Step 2 - audit NTFS permissions

```powershell
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance','\\FS01\Shared\HR' `
    -ExpandGroups -OutputFolder C:\Audit\Run1
```

This only needs ordinary NTFS read + read-permissions access to the paths
being scanned, and (optionally) AD read access for identity details --
nothing DFS-specific, nothing that requires a particular module beyond the
in-box .NET Framework (`System.DirectoryServices.AccountManagement`, no RSAT
`ActiveDirectory` module needed). If you're not sure AD lookup will work in
your environment, run once with `-NoAdLookup` to confirm the core NTFS scan
works regardless, then drop it once you've confirmed AD connectivity.

Common variants:

```powershell
# Quick pass, folders only, no AD/group expansion (fastest, fewest dependencies)
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -NoAdLookup

# Full depth incl. files where they differ from the folder ACL, groups expanded
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -IncludeFiles -ExpandGroups

# Limit recursion depth (e.g. first 3 levels only, for a huge tree)
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared' -MaxDepth 3

# Only the share root itself, no subfolders at all
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -NoRecursion

# Verbose: log every folder entered, every ACL read, every identity/group resolved
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -Verbose
```

`-NoRecursion` scans only the given root folder(s) (plus their files, if
`-IncludeFiles` is also set) -- no subfolders at all. It's equivalent to
`-MaxDepth 0` but reads more clearly in scripts/scheduled tasks, and takes
precedence if both are supplied.

`-Verbose` is the standard PowerShell common parameter and prints per-folder
traversal, every ACL read, cache hits/misses on identity resolution,
group-expansion results, and buffer flushes to disk -- useful for confirming
a scan is progressing (and where) on a large tree, or for troubleshooting a
run that stalls. `Get-FileServerShareInventory.ps1` supports `-Verbose` the
same way.

## Reading the output

**Per-folder-tree view (`FolderPermissions.csv`)** -- "what can happen in this
folder?" One row per ACE per object:

| Column | Meaning |
|---|---|
| `Path` | Folder or file path |
| `InheritanceBrokenHere` | `True` if this folder's ACL is protected (does **not** inherit from its parent) -- the folder-level flag |
| `IdentityName` / `IdentityType` | Resolved account/group and whether it's a User/Group/Computer/Well-known/Unresolved |
| `RightsSummary` | `Full Control` / `Modify` / `Read & Execute` / `Read` / `Write`, or `Special` |
| `RightsDetail` | Exact granular rights (always populated; the breakdown you asked for behind "Special") |
| `IsInheritedAce` | `True` if this specific ACE came from the parent, `False` if explicit at this object |
| `AppliesTo` | Plain-English inheritance scope, e.g. "This folder, subfolders and files" |

Filter to `InheritanceBrokenHere = True` or `IsInheritedAce = False` to see
only where permissions deviate from the parent -- usually what you actually
want to review on a mature share.

**Per-identity view (`IdentityPermissions.csv`)** -- "what does this
person/account have access to, anywhere?" Same rows, pivoted so you can
filter/group by `IdentityName` first. If `-ExpandGroups` was used, each group
ACE also produces one row per effective (recursively nested) member, with
`GrantedViaGroup` showing which group granted it -- so a user who's only ever
added to groups still shows up directly against every path they can reach.

**AD identity details (`ADIdentityDetails.csv`)** -- "who actually is this
account, and should they still have access?" One row per unique identity
encountered anywhere in the scan (every ACE, plus every member pulled in via
`-ExpandGroups`), joinable to the other two reports on `IdentitySid`:

| Column | Meaning |
|---|---|
| `DisplayName`, `Title`, `Department`, `Office`, `TelephoneNumber`, `EmployeeId`, `Manager` | HR/org context, pulled from AD |
| `Enabled`, `LockedOut`, `AccountExpirationDate` | Is the account currently usable at all |
| `PasswordNeverExpires`, `PasswordLastSet` | Password hygiene |
| `LastLogonTimestampApprox` | Approximate last domain logon -- see caveat below |
| `WhenCreated` | When the account was created |
| `GroupScope`, `GroupCategory`, `DirectMemberCount`, `ManagedBy` | Populated instead of the user columns when the identity is a Group |
| `LookupNotes` | Explains why a row has little/no data (well-known SID, AD lookup disabled, unresolved SID, etc.) |

Filter this to `Enabled = False` or an old `LastLogonTimestampApprox` and join
back to `IdentityPermissions.csv` on `IdentitySid` to find exactly which
paths a disabled or dormant account still has access to -- the core "are
these people still here, and should they still have this" question. Note:
`LastLogonTimestampApprox` reads AD's replicated `lastLogonTimestamp`
attribute, which can lag the true last logon by up to ~14 days by design --
treat it as approximate, not to-the-day precise.

**`InheritanceExceptions.csv`** -- a flat list of every folder where
inheritance is broken, for a fast "where did someone click 'Disable
inheritance'" sweep without wading through the full per-ACE report.

**`Errors.log`** -- anything the scan couldn't read (permission denied on the
scanning account, path length issues, etc.), so gaps in coverage are visible
rather than silent.

### Step 3 (optional) - interactive access map

```powershell
.\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1
```

Produces `AccessMap.html` in that folder. Double-click it -- it's a single,
self-contained file with everything (data, CSS, JS) embedded inline, so it
opens straight from disk with no server, no database, no internet access,
and no separately-installed JavaScript library. (There isn't really a
mainstream "BloodHound for NTFS permissions" -- BloodHound itself maps AD
relationships, not filesystem ACLs, and needs a Neo4j server; the tools that
do map filesystem access, Sysinternals AccessChk/AccessEnum, the
NTFSSecurity module, commercial products like Varonis/Netwrix, are either
CLI/text-only or need their own agent and server. This turns the CSVs you
already have into the closest practical equivalent.)

What it gives you:

- **Search/browse** identities or folders in the left sidebar.
- **Select an identity**: an info card (title, department, manager, enabled/
  locked/last-logon from `ADIdentityDetails.csv`), a radial graph of the
  folders they can reach, and a full sortable table of every path (with
  rights, inherited/broken-here, and which group granted it if any) --
  click any row/node to pivot straight to that folder.
- **Select a folder**: the mirror image -- who has access, via which group,
  and whether it's inherited.
- **Quick filters**: "Broken inheritance folders" and "Disabled/dormant
  identities" (no logon in 90+ days, or disabled/locked) jump straight to
  the two things a review usually cares about most.
- **Export to CSV** from any table (respecting whatever you've typed into
  that table's own filter box) via a button -- generated client-side in the
  browser, no server round-trip.
- A **Back** button to retrace your clicks as you pivot between nodes.

The radial graph for a single node caps at the 60 most notable neighbors
(explicit/non-inherited access and higher rights levels first) to stay
readable and fast without a query engine behind it -- the complete,
uncapped list is always in the sortable table right below the graph, and is
what gets exported.

`-MaxEdgesPerNode` (default 60) controls that cap. For very large audits
(hundreds of thousands of rows), the whole dataset is embedded as JSON in
the one HTML file, which can get large (tens of MB) -- still workable, but
if it feels sluggish, generate a map per share/subtree rather than one for
the whole server.

**`Build-AccessMapHtml.ps1` needs `AccessMapTemplate.html` in the same
folder** (it fills in the data and writes the result as `AccessMap.html`) --
keep the two files together.

## Notes and caveats

- **Run as an account with Read + Read-Permissions on every path being
  scanned**, and read access to AD if you want `ADIdentityDetails.csv`
  populated. No RSAT `ActiveDirectory` module is required for that -- it uses
  `System.DirectoryServices.AccountManagement`, part of the .NET Framework
  that ships with PowerShell 5.1.
- **Share-level vs NTFS-level permissions are different layers.** A user's
  effective access to a share is the intersection of `Shares.csv`'s
  `ShareLevelAccess` and whatever `FolderPermissions.csv` says at the share's
  root. Most shares are set to Everyone/Authenticated Users Full Control at
  the share level with NTFS doing the real restricting, but confirm this
  rather than assume it.
- **`-IncludeFiles` is expensive.** By default only folders are scanned;
  explicit (non-inherited) file ACEs are still always captured when
  `-IncludeFiles` is on, since those are exactly the anomalies you want to
  catch. Add `-IncludeInheritedFileAces` only if you need every single file
  row logged too (very large output on big shares).
- **Very long paths (>~248 chars):** the script attempts a `\\?\UNC\` prefix
  fallback, but extremely deep trees may still fail -- these are logged to
  `Errors.log` rather than aborting the whole run.
- **DFS access levels, summarized:**
  - Browsing a DFS path and resolving it to its physical target (`-DfsPath`):
    needs only ordinary read access to the path. No RSAT, no DFS admin rights.
  - Enumerating the *entire* namespace tree to discover folders you don't
    already know about (`-DfsNamespace`): needs the DFSN RSAT module *and*
    rights to read the namespace configuration -- a materially higher
    privilege tier. If you don't have that, `-DfsPath` with the paths you
    already know covers the actual audit need.
  - The NTFS audit itself never needs any of the above -- it can scan a DFS
    path directly and let Windows resolve the referral, or a physical path,
    with identical results either way.
  - If DFS truly can't be queried at all -- not even `-DfsPath`'s client
    referral trick (DFS client blocked/disabled, firewalled, unreachable
    from where you're running this, etc.) -- see
    **[Manual-DFS-Verification.md](Manual-DFS-Verification.md)** for a
    step-by-step checklist of what to check by hand instead (an Explorer GUI
    trick that needs no special rights at all, how to tell which physical
    node your session is actually using, and an honest list of what
    genuinely requires asking someone with server/DFS-management access,
    rather than something you can work around alone).
