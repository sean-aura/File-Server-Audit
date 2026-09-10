# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Initial release

### Added

**`Invoke-NTFSPermissionAudit.ps1`**
- Walks folder (optionally file) trees and captures full ACL detail per
  object: identity, allow/deny, explicit vs. inherited, inheritance scope
  decoded to plain English, and rights decoded to the same basic-permission
  labels the Windows ACL editor shows (Full Control / Modify / Read &
  Execute / Read / Write) or "Special" with the exact granular rights
  listed.
- Recursive group-membership expansion and AD identity/account-state
  lookup via `System.DirectoryServices.AccountManagement` -- no RSAT
  `ActiveDirectory` module required.
- Four report outputs from a single pass:
  - `FolderPermissions.csv` -- per-folder-tree view (one row per ACE per
    object).
  - `IdentityPermissions.csv` -- per-identity/pivoted view, with a
    `GrantedViaGroup` column when `-ExpandGroups` is used.
  - `ADIdentityDetails.csv` -- one row per unique identity encountered
    anywhere in the scan (title/department/office/phone/employee ID/
    manager, enabled/locked/expired, password age, approximate last logon,
    creation date; scope/category/member count/managed-by for groups),
    joinable to the other two by `IdentitySid`.
  - `InheritanceExceptions.csv` -- every folder with broken inheritance.
  - `Errors.log` -- access-denied/path-too-long failures logged rather
    than aborting the run.
- Iterative (stack-based) tree walk to avoid recursion-depth limits on deep
  trees; `\\?\` long-path fallback near MAX_PATH.
- Parameters: `-Path`, `-IncludeFiles`, `-IncludeInheritedFileAces`,
  `-MaxDepth`, `-NoRecursion`, `-ExpandGroups`, `-ExpandGroupsExclude`,
  `-SkipInheritedAcesInFolderReport`, `-OutputFolder`, `-NoAdLookup`,
  `-Verbose` (with real diagnostic output: per-folder traversal, ACL reads,
  identity/group-member cache hits, buffer flushes).

**`Get-FileServerShareInventory.ps1`**
- Enumerates non-default SMB shares and share-level ACLs across one or more
  servers, guarded with `Get-Command` checks -- degrades to a warning +
  skip rather than a hard failure if the `SmbShare` module isn't present.
- `-DfsPath` resolves one or more already-known DFS paths to their physical
  target(s) via the Win32 `NetDfsGetClientInfo` API -- the same
  client-side referral lookup Windows performs when a path is opened in
  Explorer. No DFS admin rights or RSAT `DFSN` module required, only
  ordinary read access to browse the path. Reports whether each target is
  currently the *Active* one, not just Online.
- `-DfsNamespace` offers full namespace-tree enumeration via the `DFSN`
  module (`Get-DfsnFolder`/`Get-DfsnFolderTarget`, walking nested DFS
  folders) as an explicitly optional, higher-privilege bonus if that access
  is also available; skipped with an explanatory message otherwise.
- Parameters: `-ComputerName` (optional), `-DfsPath`, `-DfsNamespace`,
  `-NoRecursion` (applies to DFS folder discovery), `-OutputFolder`,
  `-Verbose`.

**`Build-AccessMapHtml.ps1`** + **`AccessMapTemplate.html`**
- Turns the audit CSVs into a single, self-contained, interactive HTML
  file -- no server, no database, no external JS libraries, opens directly
  from disk over `file://`.
- Search/filter identities and folders; select one to see a radial "ego
  network" graph of its access relationships (capped at `-MaxEdgesPerNode`
  most notable neighbors, default 60, explicit access and higher rights
  first) plus a full sortable table underneath with everything, each
  row/node clickable to pivot.
- Quick filters for broken-inheritance folders and disabled/dormant
  identities (no logon in 90+ days, disabled, or locked).
- Per-table CSV export via a client-side Blob download; Back-button
  navigation across pivots.
- All data embedded as JSON directly in the HTML, so it works fully
  offline at both generation and view time.

**Documentation**
- `README.md` -- full workflow, report-column reference, and access-level
  caveats (share-level vs. NTFS-level permissions being distinct layers,
  DFS access-tier summary, `-IncludeFiles` cost, long-path limitations).
- `Manual-DFS-Verification.md` -- step-by-step checklist for hand-verifying
  DFS topology when no tooling (not even `-DfsPath`) can query it at all,
  plus an explicit list of what genuinely requires server/DFS-management
  access to check.
- `LICENSE` -- MIT.

### Fixed
- AD large-integer conversion (`lastLogonTimestamp`) was recombining the
  `HighPart`/`LowPart` 32-bit halves using double-precision arithmetic,
  which silently loses precision above 2^53 and produced wrong dates (a
  known 2026 date round-tripped as year 2452 in testing). Rewritten using
  pure `Int64` bitwise shift/OR.

### Testing notes
- All PowerShell parsed clean against the PS7 language parser.
- Rights-decoding logic unit-tested against known-good `FileSystemRights`
  decimal values, confirmed to match Windows ACL editor labels.
- The corrected large-integer conversion was round-trip tested against
  four dates spanning 1601-2040.
- The `NetDfsGetClientInfo` P/Invoke signature and struct layouts compile
  cleanly with expected native sizes; the actual `Netapi32.dll` call
  couldn't be exercised outside a Windows/DFS environment -- a first run
  against one known path is recommended before relying on it broadly.
- The HTML/JS report was executed and exercised via headless DOM (jsdom)
  against real generated output: search/filter, identity and folder
  selection, table sorting, both quick filters, CSV export, and
  back-navigation all verified programmatically, first on a small dataset
  then a synthetic 420-identity/50-folder/4,000-edge dataset to confirm
  capping logic holds at scale. Visual layout has not been confirmed in an
  actual browser.
