# File Server Permission Audit Toolkit

Three scripts for auditing NTFS/share permissions on a DFS-fronted Windows
file server pair (one active node, one standby), plus a self-contained
interactive HTML report. Works under both Windows PowerShell 5.1 and
PowerShell 7+.

Version 0.6.2. Licensed under the MIT License -- see [LICENSE](LICENSE).

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
   Errors_<timestamp>.log      (access-denied / path-too-long, etc.)
        |
        v
3. Build-AccessMapHtml.ps1            -- OPTIONAL: turn the CSVs into an
        |                                 interactive HTML report
        v
   AccessMap_<timestamp>\
     AccessMap.html        (open directly in a browser, no server required)
     AccessMap_data\       (its data -- keep the two together)
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

# Lean output: skip purely-inherited ACEs entirely (both CSVs), keeping only
# explicit ACLs and each folder's inheritance-broken flag -- recommended when
# the output will feed Build-AccessMapHtml.ps1's tree view
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared\Finance' -SkipInheritedAces

# Scan level by level (root, then all its children, then all of THEIR
# children, etc.) instead of one branch all the way down at a time --
# recommended for a very large tree you might not finish scanning in one
# sitting, so an interrupted run still covers the top of every branch
# rather than the whole depth of just one
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared' -BreadthFirst

# Process ACL reads and identity resolution for several objects at once
# instead of one at a time -- PowerShell 7+ only; see the caveat below
# before picking a number
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared' -ThrottleLimit 8

# Continue a previous run that got interrupted (killed, crashed, a reboot)
# before finishing, instead of starting over -- must point -OutputFolder at
# the SAME folder the interrupted run used, and every other parameter must
# match exactly (the script checks and refuses if anything's different)
.\Invoke-NTFSPermissionAudit.ps1 -Path '\\FS01\Shared' -OutputFolder C:\Audit\Run1 -Resume
```

`-BreadthFirst` changes only the *order* objects are visited and written,
not what gets scanned or the final CSV contents -- the folder hierarchy in
`Build-AccessMapHtml.ps1`'s tree view is reconstructed from each row's own
path string, never from scan order, so **this has no effect on HTML
generation either way.** The reason to use it: if a scan of a very large
share gets interrupted partway through (killed, times out, a reboot), the
default depth-first order leaves you with one fully-scanned branch and
nothing else, while breadth-first leaves you with the top few levels of
*everything* -- and that partial result is exactly what the tree view
already displays well by default (a shallow-but-complete tree looks
identical to an intentionally `-MaxDepth`-limited run; nothing extra
needed on the HTML side to make use of it). The trade-off: on a very
wide, shallow share (many thousands of top-level folders), breadth-first
can hold more pending folders in memory at once than depth-first would,
since it fully visits one level before starting the next -- rarely
significant in practice (each pending item is just a path and a depth
number), but a real characteristic difference.

`-SkipInheritedAces` matters more than it might look: a plain recursive scan
records the same inherited ACE on *every* folder down an unbroken inheritance
chain (a share with 10,000 folders and 5 inherited ACEs each produces ~50,000
near-duplicate rows). With it on, a folder's absence from the output means
"unchanged from its parent", and any row means "something explicit is set
here" -- smaller CSVs, a smaller generated HTML file, and per-folder access
counts in the tree that actually mean something. (Older scripts using the
previous parameter name, `-SkipInheritedAcesInFolderReport`, still work --
it's kept as an alias.)

`-NoRecursion` scans only the given root folder(s) (plus their files, if
`-IncludeFiles` is also set) -- no subfolders at all. It's equivalent to
`-MaxDepth 0` but reads more clearly in scripts/scheduled tasks, and takes
precedence if both are supplied.

`-ThrottleLimit N` (default 1, meaning fully sequential -- nothing changes
unless you opt in) processes N objects' ACL reads and identity resolution
concurrently instead of one at a time. **Requires PowerShell 7+** -- the
underlying mechanism (`ForEach-Object -Parallel`) doesn't exist in Windows
PowerShell 5.1, and passing a value above 1 there is a clear, immediate
error rather than a silent fallback to sequential. Why this helps: on a
large share the bottleneck is almost always I/O latency (a network
round-trip per ACL read, plus AD round-trips the first time each identity
is seen), not CPU, so doing several of those waits at once can cut
wall-clock time substantially. Only the expensive per-object work is
parallelized; directory/file discovery itself stays sequential (cheap,
and keeps `-BreadthFirst`/`-MaxDepth`/`-NoRecursion` behaving exactly as
documented). Two caches -- a Sid-to-Name/Type label cache and a
group-membership-expansion cache -- are shared across all workers via a
thread-safe `ConcurrentDictionary`, so the cross-object caching benefit
that already existed sequentially isn't lost under parallelism; both
deliberately hold only plain data, never a live AD object, since those
aren't safe to use from a thread other than the one that resolved them.

**The honest performance finding, measured rather than assumed**:
`ForEach-Object -Parallel` has its own fixed per-item dispatch overhead
(on the order of a couple of milliseconds each). Whether `-ThrottleLimit`
helps or actively hurts depends entirely on whether your real per-object
ACL-read latency exceeds that overhead. Testing against a synthetic
15ms-per-item delay (a plausible stand-in for a real SMB round-trip),
`-ThrottleLimit 16` measured roughly **6x faster** than sequential for
the same workload. Testing against near-zero-latency work (nothing to
actually wait on), the fixed per-item overhead made parallel processing
measurably *slower* than sequential -- not just "no better." There's no
free lunch here: **benchmark `-ThrottleLimit` against a small,
representative sample of your actual share before committing to a value
for a multi-hour scan**, since the right answer depends on your network,
file server, and AD topology, not just the size of the tree. A reasonable
starting point to try is somewhere in the 4-16 range; a heavily-loaded or
older file server can itself become the bottleneck (or start throttling
connections) under too much concurrent load, so higher isn't automatically
better.

`-Resume` continues a run that was interrupted (killed, crashed, the
machine rebooted) before finishing, instead of starting the whole scan
over. **Requires an explicit `-OutputFolder`** pointing at the same folder
the interrupted run used -- `-OutputFolder`'s default value bakes in the
current timestamp, so relying on it here would almost certainly point at
a brand-new, empty folder instead. Every run writes a small
`RunConfig_<timestamp>.json` (every parameter that affects what gets
scanned or how) and a `Checkpoint_<timestamp>.txt` (every object fully
processed *and* durably written to the CSVs -- specifically never marked
done before that, so a crash between "processed" and "written to disk"
can't silently lose data; worst case, that one object's work is simply
redone). `-Resume` finds the most recent run in `-OutputFolder` without a
matching `Completed_<timestamp>.marker`, checks that every parameter from
this invocation matches what was recorded, and -- only if they all match
-- continues appending to that same run's files, skipping anything
already checkpointed. A mismatched parameter (a different `-ThrottleLimit`,
`-BreadthFirst`, `-Path`, anything) is a clear, specific error rather than
a guess about which settings should win.

Tested against real interruptions, not just simulated ones: `kill -9`
mid-scan at multiple points (including deliberately between one checkpoint
flush and the next, so some objects are processed but not yet durable),
across both sequential and `-ThrottleLimit` modes -- the resumed run's
final result is byte-for-byte identical to an uninterrupted run of the
same tree, with no gaps and no duplicate rows.

**The trade-off you're accepting**: anything already scanned before the
interruption is *not* re-checked, even if it changed in the meantime -- a
folder whose permissions were modified after it was scanned would still
show its older permissions in the final report. For most large-scan
interruptions this is clearly the right trade (re-scanning everything
costs far more than this staleness risk), but it's worth knowing about.

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

**`Errors.log`** (written as `Errors_<timestamp>.log`, matching the run) --
anything the scan couldn't read (permission denied on the scanning
account, path length issues, etc.), so gaps in coverage are visible
rather than silent.

### Step 3 (optional) - interactive access map

```powershell
.\Build-AccessMapHtml.ps1 -InputFolder C:\Audit\Run1
```

Produces a timestamped folder (e.g. `AccessMap_20260910_211500\`) inside
`C:\Audit\Run1` containing `AccessMap.html` plus an `AccessMap_data\`
subfolder. Double-click `AccessMap.html` -- it needs no server, no database,
no internet access, and no separately-installed JavaScript library, so it
opens straight from disk. Its data lives in the sibling `AccessMap_data\`
folder and is fetched lazily, one top-level share at a time, as you actually
open things -- keep the two together (copy/zip/email the whole output
folder) since the HTML file can't load its data on its own. (There isn't
really a mainstream "BloodHound for NTFS permissions" -- BloodHound itself maps AD
relationships, not filesystem ACLs, and needs a Neo4j server; the tools that
do map filesystem access, Sysinternals AccessChk/AccessEnum, the
NTFSSecurity module, commercial products like Varonis/Netwrix, are either
CLI/text-only or need their own agent and server. This turns the CSVs you
already have into the closest practical equivalent.)

**Offline Linux/macOS variant.** `Build-AccessMapHtml.sh` (+ its companion
`build.awk`, both need to sit alongside `AccessMapTemplate.html` just like
the PowerShell script does) produces the exact same `AccessMap.html` +
`AccessMap_data\` output from the same CSVs, entirely without PowerShell --
useful for building the report on a Linux/macOS box, in CI, or anywhere
PowerShell isn't installed:

```bash
./Build-AccessMapHtml.sh -i /audit/Run1
# or: -o OUTPUT_FOLDER, -m MAX_EDGES_PER_NODE, -f/--force -- run --help for all of them
```

It needs only `bash` and a standard `awk`. It reads the CSVs itself rather
than shelling out to the `.ps1` files, so `Invoke-NTFSPermissionAudit.ps1`
still has to have actually run (on Windows, where it needs
`System.DirectoryServices`) to produce them first; only this last,
platform-independent step moves to bash. Verified to produce semantically
identical output to `Build-AccessMapHtml.ps1` for the same input (same
identities, folders, edges, and every dashboard aggregate -- confirmed with
a structural diff, not just "it didn't crash") against both **gawk** and
**mawk**, byte-identical between the two. It has *not* been run against
macOS's own built-in awk (a BWK/"one true awk" derivative) -- the script
deliberately avoids gawk-only features so it's expected to behave the same
there, but that expectation is untested, not verified, on this project so
far.

Its CSV parser handles the cases that actually matter for this data:
quoted fields containing commas (the common case -- `RightsDetail`, for
instance), doubled `""` quote-escaping, `\r\n`-terminated files (a stray
trailing `\r` is stripped from every line before it's used, so a
Windows-authored CSV parses the same as a Unix-authored one), and -- via a
standard technique, counting `"` characters and treating an odd running
total as "still inside a quoted field" -- a field that legitimately
contains a literal embedded newline, reassembling it correctly across
however many physical lines it spans. None of this data's actual columns
carry free-form multi-line text in practice, but the parser doesn't have to
assume that; it detects and handles it either way, and the build's own
summary output says so when it happens (`N row(s) had a quoted field
containing a literal newline...`). The one remaining thing worth knowing:
`identities[]`/`folders[]` array ORDER can come out differently from a
PowerShell-built report for the same input (this script doesn't replicate
the PowerShell version's SID-sort seeding order) -- the data is equivalent
either way, since nothing in `AccessMap.html` depends on array order.

What it gives you:

- **A Summary view, shown by default on open** (and reachable any time via
  the **Summary** button in the header): a single-screen digest instead of
  scattered numbers, meant to answer "what's the state of this share"
  without drilling into individual folders first --
  - **An incomplete/truncated-data warning, shown automatically when it
    applies** (a red banner at the top of the Summary view, plus a small
    persistent badge next to the Summary button visible from anywhere in
    the report): if the source scan was interrupted before finishing (no
    matching `Completed_<timestamp>.marker` -- see `-Resume` above) and/or
    a source CSV's last line was cut off mid-write (the file doesn't end
    with a newline -- the one incomplete row is dropped, everything else
    in the file is unaffected), the report says so plainly rather than
    silently showing a partial picture as if it were the whole one.
    Everything successfully captured is still shown normally throughout.
  - **Top-line counts**: identities total, users (split enabled/disabled),
    groups, computer/service accounts, folders scanned, folders with broken
    inheritance, disabled/dormant identities, and objects that couldn't be
    scanned at all -- each of the last four clickable straight through to
    the filtered list or detail behind it.
  - **Folders that couldn't be scanned**: parsed from the audit's
    `Errors.log` (access denied, path-length limits, etc.) -- these
    wouldn't otherwise show up anywhere, since they have no ACL data to
    display, so without this they'd be invisible blind spots rather than a
    flagged, reviewable list. Exportable to CSV.
  - **Access rights distribution**: a donut chart plus legend showing what
    share of all access grants are Full Control vs. Modify vs. Read &
    Execute, etc.
  - **What each access level actually allows, and how it could be
    misused** -- a plain-language reference table (Full Control through
    Read), since "Modify" and "Full Control" sound similar but the gap
    between them (changing permissions/ownership) is exactly the kind of
    thing worth knowing when judging how risky a grant is.
  - **Observations worth a closer look**: a small set of data-driven
    findings -- broad/default groups (Everyone, Authenticated Users, Domain
    Users) holding Full Control or Modify; broken inheritance; disabled,
    locked, or dormant identities that still have active access; orphaned
    SIDs still on ACLs; a high share of Full Control overall -- each with a
    plain-language explanation of why it matters, and specific normative
    guidance (paraphrased, not quoted verbatim) tagged by region: **AU**
    (ACSC Essential Eight maturity-level requirements, and the Australian
    Government ISM's cybersecurity principles), **NZ** (specific NZISM
    control references, e.g. "16.4.38.C.01"), **US** (named NIST SP 800-53
    control IDs like AC-6/AC-2(3), and NIST CSF 2.0 subcategories), and
    **Intl** (CIS Controls v8 safeguards). Where a finding is a genuine,
    directly-legislated requirement in one of these frameworks (least
    privilege, disabling stale accounts), the guidance says so specifically
    with a "MUST"/control-ID level of detail rather than just naming the
    framework; where the connection is more general (e.g. broken
    inheritance isn't a named rule in any of these, just a configuration-
    hygiene concern), the tool says that too, rather than overstating it.
    **These are a heuristic, data-driven starting point for a conversation
    with your security/compliance team, not a certified compliance
    assessment** -- the tool says this in the UI too, and since these
    frameworks are periodically revised, check the current authoritative
    source (ACSC, GCSB/NCSC-NZ, NIST, CIS) before treating any of this as a
    compliance determination either way.
- **Search/browse** identities or folders in the left sidebar.
- **Select a folder**: an info card (inheritance status), a collapsible
  **folder/subfolder tree** rooted at that folder, and a full sortable table
  of every identity with access to it (rights, inherited, deny, granted via
  group) -- click any subfolder in the tree, or any row in the table, to
  pivot straight there.
- **Select an identity**: an info card (title, department, manager, enabled/
  locked/last-logon from `ADIdentityDetails.csv`), the **same kind of tree**
  but with one root per folder that identity directly accesses (so someone
  with access to three unrelated shares sees three independent trees), and a
  full sortable table of every path they can reach.
- **Two ways to look at whatever's selected, in tabs**: **Tree** (the
  folder/subfolder hierarchy described below) and **Graph** (a picture --
  the selected folder or identity in the center, with its relationships
  arranged around it in concentric rings, color-coded by rights, draggable,
  zoomable, and pannable). Your tab choice carries over as you navigate.
  The Graph tab has its **own depth control** (1 / 2 / 3 / 4 / 5 / Full,
  separate from the Tree's -- they mean different things: relationship
  hops here vs. subfolder nesting there), defaulting to 1 (direct
  relationships only). Beyond hop 1, the same hub-safe traversal rules
  apply as everywhere else in this tool: groups, well-known accounts
  (Everyone, SYSTEM, etc.), and unusually high-fan-out accounts (an
  admin/service account with hundreds of grants) only reveal their own
  direct reach when they're the one actually selected -- otherwise a
  single shared group could bridge two unrelated parts of the tree
  together into one tangled picture. Click any node to make it the new
  selection and follow the chain further.
- **The tree**: this is deliberately a folder/subfolder hierarchy, not a
  relationship graph -- it mirrors what you'd see in Explorer, with each
  folder's own children branching from it specifically (a subfolder's
  children are never pooled with a sibling folder's). This also means
  there's no way for something unrelated to leak into view the way a
  general relationship graph could: a tree rooted at (or including) a
  folder only ever shows what's actually inside that folder.
  - **Depth control** (1 / 2 / 3 / 4 / 5 / Full): how many *levels of
    subfolder nesting* to auto-expand. 1 = just the folder itself, nothing
    expanded. 2 = + its direct subfolders. 3 = + their own subfolders in
    turn (each still branching from its own parent). Full expands
    everything found in the data, up to a safety cap on very large trees.
  - **Manual expand/collapse**: click the \u25b8/\u25be triangle on any folder to
    expand or collapse it by hand, independent of the depth setting --
    useful for drilling into one specific branch without expanding
    everything else too.
  - **Click a folder's name** (not the triangle) to select it -- updates
    the info card and table above/below to that folder, and pushes it onto
    the **Back** history.
  - Each row shows a small badge with how many access entries that folder
    has, and a "broken" badge if inheritance is broken there. If the source
    audit ran without `-SkipInheritedAces`, this count includes inherited
    ACEs too, so it'll repeat the same number down an unbroken chain --
    still correct, just less immediately informative than a run with that
    switch on.
- **Quick filters**: "Broken inheritance folders" and "Disabled/dormant
  identities" (no logon in 90+ days, or disabled/locked) jump straight to
  the two things a review usually cares about most.
- **Export to CSV** from any table (respecting whatever you've typed into
  that table's own filter box) via a button -- generated client-side in the
  browser, no server round-trip.
- A **Back** button to retrace your clicks as you pivot between folders/identities.

Since there's no query engine behind a static file, a folder with more
subfolders than `-MaxEdgesPerNode` (default 60) shows only that many in the
tree, with a "+N more" note -- select the folder itself and use the table
for the complete list. Auto-expansion at "Full" depth also stops after 1,500
folders on a very large tree, to stay responsive; anything still collapsed
past that point can still be expanded manually.

For very large audits (hundreds of thousands or millions of rows), access
entries are partitioned into one file per top-level share
(`AccessMap_data\share_N.js`) and loaded lazily -- only the share(s) you
actually open get fetched, so the dashboard, sidebar search, and quick
filters render instantly regardless of overall size, and opening a specific
folder or identity only costs whatever its own share weighs. If a single
share is itself huge, opening something inside *that* share can still feel
slow (its one file is still large); keeping the depth setting low helps
there, same as before.

**`Build-AccessMapHtml.ps1` reads `IdentityPermissions.csv`/`ADIdentityDetails.csv`
as a true stream** (one row at a time via a quote-aware CSV parser), not by
loading the whole file into memory as `Import-Csv` does -- a real, structural
difference on a very large file, since `Import-Csv` must hold every row
simultaneously by design. This measurably raises how large a source file the
*build* step can get through without running out of memory. It comes with an
honest trade-off, not a free win: streaming is meaningfully **slower** in
wall-clock time than `Import-Csv` on a file that would have fit in memory
anyway (confirmed directly: roughly 3 minutes for 800,000 rows in testing) --
worth knowing if you're scanning something modest in size, where the old
behavior would have been faster.

**The *browser* no longer has a fundamental size ceiling the way it used to**
-- the old version embedded the entire dataset as one inline JSON blob, so
opening the report cost a multi-hundred-MB parse before anything rendered at
all, regardless of what you actually wanted to look at. Now it only ever
loads what you ask for. **This build *script* still has one, though**: it
accumulates every identity/folder/access-entry in memory while it streams
the CSV (each row's .NET object overhead is larger than the row's own text),
and only partitions/writes them out to `AccessMap_data\` at the end. A
warning appears automatically once `IdentityPermissions.csv` exceeds roughly
300 MB, since that's the point where running into trouble while *building*
the report becomes a real possibility. **The fix for a source file at that
scale isn't a bigger machine -- it's scanning and mapping one share/subtree
at a time** (re-run `Invoke-NTFSPermissionAudit.ps1` with `-Path` pointed at
each major share separately, and build a map per share) rather than one
combined report for an entire file server. This is already fully supported
today, nothing new to learn.

Like the CSVs, `Errors.log` is picked up automatically from `-InputFolder`
if present (matching the same run by timestamp) -- nothing extra to pass.
If it's missing entirely, the Summary view's "could not be scanned" count
just shows 0 rather than erroring, since an older run or a clean scan with
nothing to report both look the same from here -- **which means a 0 there
doesn't always mean "clean scan."** The same silent-0 behavior also
happens if `Build-AccessMapHtml.ps1` itself predates this feature, or if
you're pointing it at a different folder than the one the audit actually
wrote to. If you know there were scan errors but the report shows 0,
check, in order: (1) does the generated `AccessMap.html`'s footer say the
`toolkit v` number you expect -- an older version number there means an
older script was used to build it, regardless of which version you're
looking at right now; (2) is there actually an `Errors_<timestamp>.log`
(or plain `Errors.log`) file sitting in the exact `-InputFolder` you
passed; (3) did you regenerate the HTML *after* the run that produced
those errors, not before.

**Keep `Invoke-NTFSPermissionAudit.ps1`, `Build-AccessMapHtml.ps1` (or its
`Build-AccessMapHtml.sh` + `build.awk` bash/awk equivalent), and
`AccessMapTemplate.html` as a matched set.** Either build script needs
`AccessMapTemplate.html` sitting in the same folder to run at all -- it
reads that file and copies it byte-for-byte as `AccessMap.html` in the
output folder (its data is written separately, alongside it, as
`AccessMap_data\manifest.js` and `AccessMap_data\share_N.js` -- see Step 3
above) -- so update all of them together rather than swapping just one, and
use the generated report's footer (`toolkit vX.X.X`) as a quick sanity
check that the version you're looking at is the one you think it is.

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
- **Output files are timestamped and won't overwrite each other.** Every CSV/
  log/HTML file name includes the run's timestamp (e.g.
  `FolderPermissions_20260910_211500.csv`), so re-running into a fixed/shared
  `-OutputFolder` across multiple runs never silently clobbers a previous
  run's files -- `Build-AccessMapHtml.ps1` automatically finds the latest run
  in a folder. If a file with that exact name somehow already exists, all
  three scripts error rather than overwrite; pass `-Force` if you actually
  want to.
- **Works under PowerShell 5.1 and PowerShell 7+.** The ACL-reading code path
  differs internally between the two (a .NET Framework vs .NET Core API
  difference), handled automatically -- no action needed on your part.
- **`ADIdentityDetails.csv`'s last-logon column can be blank or stale.**
  `LastLogonTimestampApprox` depends on domain replication and history and
  isn't always populated; `WhenChanged` (AD's general last-modified
  timestamp, updated on nearly any attribute write, not just logons) is
  captured alongside it as a more consistently-available fallback signal.
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

## Troubleshooting

- **`-ThrottleLimit` parallelization only ever runs under PowerShell 7+ --
  confirmed, not just assumed.** The check (`-ThrottleLimit` above 1 AND
  not running under Core edition) happens right at the start of the
  script, before any scanning begins, and is a hard failure: passing
  `-ThrottleLimit` above its default of 1 under Windows PowerShell 5.1
  throws immediately with a clear message, rather than silently falling
  back to sequential or attempting to parallelize anyway. There is no code
  path in which parallel processing runs anywhere except PS7+. Leave
  `-ThrottleLimit` at its default (1) and the script runs exactly the same
  way it always has under 5.1.

- **A scan can hang indefinitely if a network path becomes unresponsive
  (not erroring, just hanging)** -- e.g. a share that's still mounted/
  visible but a specific server or path stops responding to requests
  entirely. Neither mode has a timeout on individual ACL reads: in
  sequential mode, one hung read halts the whole scan; under
  `-ThrottleLimit`, `ForEach-Object -Parallel` won't return until *every*
  dispatched item completes, so one permanently-hung worker will stall the
  whole run even if every other item finished cleanly and was already
  written to disk. This isn't new in this release, and isn't specific to
  `-ThrottleLimit` -- it's an inherent property of not having a per-object
  timeout in either mode. If a scan seems to have stopped progressing (no
  new `Write-Progress` updates, nothing new appended to `Errors.log` or
  the CSVs for an unexpectedly long time), that's the most likely cause.
  The practical mitigation: `-Resume` (see above) means killing a hung
  scan and continuing it is now a matter of minutes of lost work, not a
  full re-scan from scratch -- everything already completed and flushed
  before the hang is preserved.

