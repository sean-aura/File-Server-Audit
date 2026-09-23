# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.6.1] - Root-caused the \\?\UNC path prefix bug (tree fracture, bogus share key)

### Fixed -- `Invoke-NTFSPermissionAudit.ps1` (bumped to 0.5.2)
- **The real root cause of a flat-looking folder tree and stray `\\?\UNC\`
  prefixes in scanned paths.** `Get-LongPathSafe`'s own long-path prefix
  (`\\?\` / `\\?\UNC\`, applied so classic .NET IO APIs can handle paths
  near `MAX_PATH`) was supposed to be stripped back off before a path was
  stored or reported, but the strip was gated on whether the *parent*
  folder's own path was prefixed (`if ($currentPath.StartsWith('\\?\'))`).
  .NET can independently decide to hand back a prefixed *child* path based
  on the child's own resulting length, regardless of whether its parent
  needed one -- so a short, unprefixed parent with a long enough descendant
  several levels down would leak `\\?\UNC\...` into that one descendant's
  path while every folder around it stayed clean. Two folders that are
  actually the same tree ended up looking like two different addressing
  schemes: string-based parent/child matching (both in this project's own
  `AccessMapTemplate.html` and in any other tool that consumes these CSVs)
  breaks exactly at the depth where the prefix appears, and share-root
  detection collapses onto a bogus `\\?\UNC` "share" instead of the real one.
  Fixed by always attempting the strip (`-replace` is a harmless no-op when
  the prefix isn't present) instead of gating it on the parent's own state,
  in both the sequential and parallel code paths. Verified: the regex logic
  itself passes 4 hand-checked prefix/no-prefix cases, the script still
  parses cleanly, and a real directory walk on a short/unprefixed path still
  returns correct, unchanged output (no regression for the common case).

### Fixed -- `Build-AccessMapHtml.ps1` / `Build-AccessMapHtml.sh`+`build.awk`
  (both bumped to 0.6.1)
- **Defensive path normalization** for CSVs captured before the fix above
  (can't be re-scanned just to pick it up): both build scripts now strip a
  leading `\\?\UNC\` or `\\?\` from every row's `Path` at ingestion time,
  before anything else (share-key derivation, folder indexing) touches it.
  Applied identically in PowerShell and awk; verified byte-identical
  normalization output for the same inputs under mawk and gawk.
- **Case-insensitive, and now explicitly toggleable, sort order.** Sidebar
  folder/identity lists and the folder tree's child ordering previously
  relied on plain `localeCompare()`, whose default collation isn't
  guaranteed case-insensitive across environments and could interleave
  mixed-case names in a way that looked unsorted even with a comparator
  applied. Replaced with an explicit lowercase comparison used consistently
  everywhere folders/identities are listed, and added an **A-Z / Z-A toggle
  button** in the sidebar (next to the search box) that flips sort direction
  across the sidebar list, the tree view, and an identity's multi-root
  folder view together.
- Verified end-to-end with a dataset built to reproduce the exact reported
  scenario (shallow, unprefixed home-directory-style folders alongside a
  deep descendant captured with the `\\?\UNC\` prefix, several unscanned
  intermediate levels in between): the tree now renders as one correctly-
  nested branch instead of fracturing at the prefixed folder, the share
  stays unified (not split into a bogus `\\?\UNC` bucket), and both the
  sidebar list and the tree correctly re-sort when the new toggle is
  clicked -- checked against both the PowerShell and bash/awk build paths.

## [0.6.0] - AccessMapTemplate.html: ACL duplication, flat tree, sidebar UX

All fixes below are confined to `AccessMapTemplate.html` -- the CSV input
format and both build scripts are untouched, since `Build-AccessMapHtml.ps1`
and `Build-AccessMapHtml.sh` both just copy this file byte-for-byte into the
generated `AccessMap.html` and need no script-side changes for any of this
to take effect (confirmed: both build paths still emit an identical, fixed
`AccessMap.html` from the same template).

### Fixed
- **A folder's ACL list double-counted group members.** A group's own grant
  and each of its expanded members previously rendered as separate, equally-
  counted flat rows, inflating the apparent number of identities with
  access. A direct grant for a Group identity now absorbs its own via-group
  rows as collapsible children instead, with a summary line splitting
  "N direct grants" from "M more via group membership". The folder tree's
  per-node count badge gets the same direct+viaGroup breakdown (e.g. "2+2")
  instead of one blended number. CSV export of the full flat edge list is
  unchanged.
- **The folder tree rendered flat instead of nested** when the scan hadn't
  recorded every intermediate folder level (an ACL-unchanged folder it
  skipped, etc.), which broke the parent/child chain and made deeper
  folders show up as their own disconnected tree roots. `buildFolderTree()`/
  `ensureNode()` now insert a "virtual" node (unclickable, labeled "not
  scanned") for any missing path segment needed to structurally connect two
  real folders, so a real folder several levels deep still nests under its
  true ancestor regardless of gaps in what the scan actually recorded.
- **Sidebar folder/identity lists were in raw scan/CSV order.** Both tabs
  now sort alphabetically by path/name.
- **The two header quick-filter buttons were one-shot list replacements**
  with no way to turn them back off short of switching tabs. They're now
  true 3-way toggles -- off / show-only (green, "ON") / hide (red, "HIDDEN")
  -- composing with search and tab state instead of replacing the render
  path. The dashboard's existing clickable stat cards/observations still
  jump straight to "show only" and stay in sync with the button's state.

### Added
- A draggable splitter between the sidebar and content panes (pointer-event
  based, width persisted via `localStorage`, wrapped in try/catch), plus a
  responsive breakpoint that stacks the panes vertically on narrow
  viewports.

### Verified
- jsdom test suite against both a real pwsh-generated and a bash/awk-
  generated dataset: a deliberately gapped folder path (5 levels, none of
  the 4 intermediate folders scanned) renders as one 6-node branch with the
  4 missing levels shown as virtual nodes, not two flat roots; a folder
  with a group holding Modify plus 2 members granted via that group shows
  exactly 2 top-level ACL rows (not 4), collapsed by default, expanding to
  reveal exactly its 2 members; the tri-state filter cycles off -> show-
  only -> hide -> off correctly via both the header button and the
  dashboard's stat-card entry point; the sidebar folder list comes back
  pre-sorted; the splitter's pointer handlers fire without error (full
  visual drag behavior isn't something jsdom can verify -- no real layout
  engine -- so treat that part as structurally tested only, not visually
  confirmed in a real browser). Full pre-existing regression suite
  (dashboard, cross-share lazy loading, relationship graph, scan errors)
  still passes with zero errors on both build paths after these changes.

### Considered and declined
- Moving the direct/via-group count split and the tree gap-bridging out of
  the browser and into both build scripts as precomputed manifest/share
  data. Declined for the count split (already cheap, scoped to one folder's
  already-in-memory edges -- no benefit to precomputing). Declined for
  gap-bridging too, on balance (a real but narrow win at very large folder
  counts, outweighed by duplicating trie-building logic across PowerShell
  and awk and keeping both provably equivalent, for a browser-side render
  step that would still be needed either way) -- revisit only if a specific
  large dataset actually shows a noticeable pause here.

## [0.6.0] - Access map: lazy per-share loading, offline bash/awk variant

### Added -- offline bash/awk variant of Build-AccessMapHtml
- **`Build-AccessMapHtml.sh` + `build.awk`**: a Linux/macOS bash+awk port of
  `Build-AccessMapHtml.ps1`, producing the exact same `AccessMap.html` +
  `AccessMap_data\` output from the same CSVs without needing PowerShell at
  all. Needs only `bash` and a standard `awk` (tested against gawk, mawk,
  and reasoned to be POSIX-portable to macOS's built-in awk). Mirrors the
  PowerShell script's CLI shape (`-i/--input-folder`, `-o/--output-folder`,
  `-m/--max-edges-per-node`, `-f/--force`), its multi-run "most recent by
  timestamp" file discovery, its truncated-last-CSV-line detection, and its
  non-empty-output-folder guard. Written without `set -e`/`set -u`/
  `set -o pipefail`, per a specific request -- every command whose failure
  matters is checked explicitly instead.
  - CSV parsing uses a hybrid strategy: a plain `split(",")` fast path for
    the overwhelming majority of rows, falling back to a quote-aware
    character-by-character parser only for rows that actually contain a
    `"` (handling embedded commas and doubled `""` quoting correctly). A
    stray trailing `\r` is stripped from every physical line before use, so
    a `\r\n`-terminated (Windows-authored) CSV parses the same as a
    Unix-authored one regardless of which column ends up last. A quoted
    field containing a literal embedded newline is detected (an odd count
    of `"` characters in the record built so far means a quoted field is
    still open) and correctly reassembled across however many physical
    lines it spans, rather than silently mis-parsed -- the build's own
    summary output reports when this happens. A file that ends with an
    unterminated quote (a genuinely malformed CSV, or the same mid-write
    kill the existing truncated-last-line check already catches, just
    landing inside a quoted field instead) is detected too and its
    incomplete last row dropped, with the two detection paths deduplicated
    so a single truncated row is never reported as two.
  - Verified against a real generated multi-share dataset (3 shares,
    broken inheritance, group membership, a broad-principal grant,
    dormant/disabled/locked identities, an unresolved SID, scan errors, a
    truncated-last-line scenario, shares with exactly one access entry, a
    genuine embedded-newline-in-a-quoted-field row, `\r\n` line endings,
    and a truncation landing inside a quoted field) with a structural diff
    against `Build-AccessMapHtml.ps1`'s output for the same input -- same
    identities, same folders (incl. `broken` flags), same per-share edge
    multisets, same dashboard aggregates (`rightsDistribution`,
    `broadPrincipalGrants`, `totalEdgeCount`, `scanErrors`) -- not just "it
    ran without crashing." Also cross-checked byte-identical output between
    gawk and mawk. NOT verified against macOS's own built-in awk (a
    BWK/"one true awk" derivative) -- the script avoids gawk-only features
    so it's expected to behave the same there, but that's an expectation,
    not something actually tested on this project so far. The only
    difference found and fixed along the way was a genuine bug (see Fixed,
    below), not a compromise accepted afterward.
    `identities[]`/`folders[]` array ORDER is not guaranteed to match the
    PowerShell version's for the same input; the data itself is
    equivalent either way.

### Fixed -- found by actually running this against generated test data
- Plain (non-boolean) AD-detail fields (`title`, `dept`, `lastLogon`, etc.)
  were emitted as JSON `null` whenever that one field happened to be blank,
  where the PowerShell version only nulls them when there's no AD detail
  record for the identity AT ALL, otherwise emitting `""` for a blank field
  on an otherwise-known identity. Functionally inert either way (`""` and
  `null` are both falsy in the JS that reads them), but the structural diff
  against the PowerShell output flagged it, so it was fixed for semantic
  parity: `sid`/`name`/`type` are now always emitted as-is (even empty),
  and the AD-lookup fields null only when no detail record exists at all.

### Changed -- `Build-AccessMapHtml.ps1` / `AccessMapTemplate.html`
- **Report output is now a folder, not one file.** `-OutputHtmlPath` is
  replaced by `-OutputFolder` (old name still accepted as an alias, but it
  now names a *directory*, not a file path). Each run writes:
  - `AccessMap.html` -- the viewer, now a byte-for-byte copy of
    `AccessMapTemplate.html`. Nothing is templated or rewritten into it
    anymore, so the template can be edited, diffed, and version-controlled
    directly, independent of any run's data.
  - `AccessMap_data\manifest.js` -- identities, folders, and every
    dashboard-level total/observation (rights distribution, broad-principal
    grants, broken-inheritance folders, dormant identities), loaded eagerly.
    Small regardless of audit size -- one entry per identity/folder, never
    per access grant.
  - `AccessMap_data\share_N.js` -- one file per top-level share
    (`\\server\share`), holding just that share's access entries (the part
    of the dataset that actually gets huge). `AccessMap.html` fetches a
    share's file via a plain `<script src>` tag (works from `file://`, no
    server, unlike `fetch()`/XHR) the moment something on screen needs it --
    a folder in that share is opened, an identity with access there is
    selected, or the relationship graph expands into it.
  - Keep `AccessMap.html` and `AccessMap_data\` together -- the HTML file
    can't load its data on its own. Copy/zip/email the whole output folder.
- **Previously, the entire dataset (every access entry, for every share) was
  embedded as one inline JSON blob in a single HTML file.** For a 1+ GB
  `IdentityPermissions.csv`, that meant the browser had to parse a
  multi-hundred-MB-to-GB string before showing anything at all -- the
  dashboard included. Now the dashboard, sidebar search, and both quick
  filters render instantly with zero access entries loaded (their
  aggregates are precomputed server-side into `manifest.js`), and opening a
  specific folder or identity only fetches the one or few shares it
  actually touches.
- `-Force` now guards writing into an existing, non-empty `-OutputFolder`
  (previously it guarded overwriting a single existing output file).
- The "large map" warning is rescoped: it used to warn about the resulting
  HTML file being slow for a *browser* to open; since the browser now only
  ever loads one share at a time, that warning now instead flags when this
  *script's own* memory use while reading a very large source CSV, or a
  single share with an unusually large number of access entries, might be
  worth splitting into a per-subtree scan.
- Bumped to 0.6.0 for both scripts to reflect this file-layout change
  (`Build-AccessMapHtml.ps1`'s own version banner; `AccessMapTemplate.html`
  has no separate version string, it inherits the toolkit's).

### Fixed -- found by actually running this against generated test data
- A share with **exactly one** access entry got its edge row corrupted into
  seven separate single-value arrays instead of one seven-value array
  (`registerShareChunk(key, [[0],[0],[3],[0],[0],[0],[-1]])` instead of
  `[[0,0,3,0,0,0,-1]]`), silently breaking that share's data. Root cause:
  `$rows = if (...) { $edgesByShare[$shareKey] } else {...}` pipes the List
  through PowerShell's success-output stream to produce the if-expression's
  value, which enumerates it -- collapsing a List with exactly one element
  down to that bare element instead of preserving it as a 1-item List (this
  is the same family of behavior as the well-known single-element-array
  ConvertTo-Json quirk noted above, just triggered by an if-expression
  assignment instead). Fixed by assigning inside each branch explicitly
  instead of relying on the if-statement's own piped-through output.

## [0.5.1] - Identity-backfill fix for -Resume, plus troubleshooting docs

### Fixed -- found during a deliberate, requested review of the 0.5.0 changes
- **`ADIdentityDetails.csv` could silently omit identities from a resumed
  scan's already-completed portion.** The parallel-mode identity backfill
  added in 0.3.0 only covered that one case; on `-Resume` (with or without
  `-ThrottleLimit`), a fresh process's identity cache only ever contains
  identities *this* invocation actually processed. Anything that only ever
  appeared in the already-checkpointed (skipped) portion of the scan --
  fully valid rows already sitting in `IdentityPermissions.csv` from
  before this invocation started -- never touched this process's cache at
  all, since those items are never re-processed by design. Reproduced with
  a targeted mock test before fixing (confirmed real identities would go
  missing), then fixed by extending the backfill to also read back the
  existing `IdentityPermissions.csv` on `-Resume` and re-resolve any
  identity not already known. Verified the actual code path (not just the
  isolated logic) via a hand-crafted resumable-run scenario.

### Documentation
- New **Troubleshooting** section in `README.md`:
  - Confirms, based on re-reading the actual gating code rather than
    re-asserting it, that `-ThrottleLimit` parallelization has no code
    path that runs, attempts to run, or silently falls back under Windows
    PowerShell 5.1 -- it's a hard, immediate failure before any scanning
    begins.
  - Documents a real, pre-existing (not introduced by `-ThrottleLimit`)
    risk: neither scan mode has a timeout on individual ACL reads, so an
    unresponsive (not erroring, just hanging) network path can stall a
    scan indefinitely -- worse under `-ThrottleLimit` in one specific way,
    since `ForEach-Object -Parallel` won't return until every dispatched
    item completes, so one permanently-hung worker blocks the whole run
    even if everything else finished cleanly. Notes `-Resume` as the
    practical mitigation if this happens.

### Testing notes
- Re-verified, with direct tests rather than assumption, two things that
  are easy to get subtly wrong: (1) grepped all three scripts for
  PS7-only syntax (ternary, null-coalescing, pipeline chain operators) --
  none found, confirming the sequential path genuinely stays PS 5.1
  compatible; (2) the RunConfig JSON round-trip correctly preserves
  single-element arrays, negative integers, and booleans across
  `ConvertTo-Json`/`ConvertFrom-Json` (a classic PowerShell gotcha is
  single-element arrays collapsing to bare scalars -- confirmed this does
  not happen here, and that the comparison logic would tolerate it even
  if it did).
- All three features combined (`-BreadthFirst` + `-ThrottleLimit` +
  `-Resume`) tested together with a real `kill -9`, completing correctly.
- Full existing suite (13 HTML/JS files, 4 PowerShell/shell files, plus
  the new identity-gap reproduction test) re-run clean.

---

## [0.5.0] - Crash recovery (-Resume) and incomplete/truncated-data handling

### Added
- `Invoke-NTFSPermissionAudit.ps1`: new `-Resume` switch. Continues a run
  that was interrupted (killed, crashed, the machine rebooted) before
  finishing, instead of starting the whole scan over. Requires an explicit
  `-OutputFolder` pointing at the same folder the interrupted run used
  (the default value bakes in the current timestamp, so relying on it here
  would point at a brand-new empty folder instead).
  - Every run now writes `RunConfig_<timestamp>.json` (every parameter
    that affects what gets scanned or how -- Path, MaxDepth, BreadthFirst,
    ThrottleLimit, ExpandGroups, etc.) and `Checkpoint_<timestamp>.txt`
    (every object fully processed and durably flushed to the CSVs). A
    finished run also gets `Completed_<timestamp>.marker`.
  - `-Resume` finds the most recent run without a matching Completed
    marker, validates every parameter from this invocation against
    RunConfig, and refuses with a specific, itemized error if anything
    differs -- never guesses which settings should win.
  - `Flush-Buffers` was restructured to use a single unified "items
    completed" trigger instead of three independent per-CSV row-count
    thresholds, specifically so a checkpoint entry is only ever written
    once that item's row data (if any) is confirmed durably on disk --
    an item can legitimately produce rows in one CSV and none in another
    (or none at all), so a per-buffer trigger could otherwise leave a
    completed item's checkpoint entry pending indefinitely.
  - Fixed, as part of building this: `ADIdentityDetails.csv` would have
    been silently overwritten (losing the original run's identity data)
    on a resumed run, since its Export-Csv call didn't previously know to
    append.
  - Documented trade-off: an object already scanned before the
    interruption is not re-checked on resume, even if it changed in the
    meantime.
- `Build-AccessMapHtml.ps1` / `AccessMapTemplate.html`: the report now
  detects and clearly flags two distinct ways source data can be
  incomplete, while still showing everything successfully captured:
  - **An interrupted scan** -- no matching `Completed_<timestamp>.marker`
    for the run's own timestamp.
  - **A truncated source file** -- a CSV whose last line was cut off
    mid-write (a killed process, not a normal completion). Detected by
    checking whether the raw file ends with a newline at all, rather than
    checking for `null` in specific fields -- a truncation partway through
    a field's *text* just silently shortens that value without producing
    any `null`, so a null-only check would miss it; the newline check
    catches truncation regardless of where in the row it happened. The one
    affected row is dropped; nothing else in the file is touched.
  - Surfaced as a prominent banner at the top of the Summary view plus a
    small persistent badge next to the Summary button, visible from any
    view in the report.

### Testing notes
- Crash recovery was tested against **real interruptions**, not simulated
  ones: `kill -9` sent to the actual process mid-scan at several points
  (including deliberately between one checkpoint flush and the next, so
  some objects are processed but not yet durable when killed), across
  both sequential and `-ThrottleLimit` (parallel) modes. In every case,
  the resumed run's final checkpoint is byte-for-byte identical (as a set)
  to a fresh, uninterrupted run of the same tree -- no gaps, no duplicate
  entries. Also confirmed: resuming an already-completed run refuses
  clearly; resuming with a changed parameter (tested with `-BreadthFirst`)
  refuses and names the mismatch; resuming without an explicit
  `-OutputFolder` refuses before touching anything.
- The truncated-file detection was verified against the actual observed
  behavior of `Import-Csv` on a genuinely truncated file (confirmed
  directly: it never throws, and a truncation can produce either a `null`
  trailing field or a silently shortened string value depending on
  exactly where it lands) rather than assumed, which is what led to
  redesigning the detection from a field-null check to the more general
  trailing-newline check.
- Full existing suite (13 HTML/JS files, 4 PowerShell/shell files) re-run
  clean after every change in this release.

---

## [0.3.0] - Parallel processing, plus three real bugs found by a deliberate code-review pass

### Added
- `Invoke-NTFSPermissionAudit.ps1`: new `-ThrottleLimit N` switch. Processes
  N objects' ACL reads and identity resolution concurrently instead of one
  at a time. Requires PowerShell 7+ (a clear, immediate error under Windows
  PowerShell 5.1, never a silent fallback); default remains 1 (fully
  sequential, unchanged behavior). Only per-object ACL/identity work is
  parallelized -- directory discovery stays sequential, so `-BreadthFirst`/
  `-MaxDepth`/`-NoRecursion` behave identically either way. Two
  thread-safe `ConcurrentDictionary` caches (identity Name/Type labels;
  group-membership expansion results) are shared across workers, holding
  only plain data -- never a live AD `Principal`/`DirectoryEntry` object,
  since those aren't safe to use from a thread other than the one that
  resolved them.
- **Measured, not assumed, performance characteristic** (documented in the
  parameter help and README): against a synthetic 15ms-per-item delay
  standing in for a real network ACL round-trip, `-ThrottleLimit 16`
  measured roughly 6x faster than sequential. Against near-zero-latency
  work, the fixed per-item dispatch overhead of `ForEach-Object -Parallel`
  made parallel processing measurably *slower* than sequential --
  documented plainly rather than oversold, with a recommendation to
  benchmark against a representative sample before committing to a value
  for a multi-hour scan.

### Fixed -- found during a deliberate, requested code-review pass, not reported bugs
- **`ADIdentityDetails.csv` would come out completely empty under
  `-ThrottleLimit`.** Parallel workers resolve identities into fresh,
  throwaway per-item caches, never into the persistent `$script:IdentityCache`
  that the final identity-details report reads from -- and the shared cache
  deliberately excludes live AD objects for thread-safety, so it can't
  substitute either. Fixed by re-resolving every distinct identity
  encountered (from the shared cache's keys) once, sequentially, on the
  main thread, after the parallel scan completes -- exactly what would
  have happened inline during a sequential scan, just deferred. Verified
  the fix's logic with a mock test, since the real Windows security APIs
  this depends on (SecurityIdentifier, AD PrincipalContext) are entirely
  unsupported outside Windows, not just the filesystem-ACL-reading part.
- **`Build-AccessMapHtml.ps1` could silently pair CSVs from two different
  audit runs.** When `-InputFolder` held output from more than one run,
  file discovery picked "most recent by filesystem `LastWriteTime`"
  independently for `IdentityPermissions*.csv`, `ADIdentityDetails*.csv`,
  and `Errors_*.log` -- which can disagree with which run a file actually
  belongs to (a file copied, restored from backup, or touched later than
  it was written). Reproduced live with a deliberately constructed
  mismatched-mtime scenario (confirmed it really did pick mismatched
  files, not just a theoretical risk), then fixed by sorting on the run
  timestamp embedded in each filename instead, which is authoritative and
  unaffected by filesystem metadata. Added as a permanent regression test.
- **Summary view's access-rights donut chart showed "1" instead of "0"**
  for a dataset with zero access entries. The divide-by-zero-safe
  denominator (falls back to 1 to avoid a `NaN` percentage) was being
  reused for the chart's displayed total as well, which is factually wrong
  when the real total is genuinely zero. Fixed by tracking the real total
  separately from the safe-for-division one.

### Testing notes
- The code review was a genuine line-by-line pass across all four files
  (both PowerShell scripts touched recently, `Get-FileServerShareInventory.ps1`,
  and `AccessMapTemplate.html`), not a superficial scan -- each of the three
  fixes above was found by reading the code critically enough to predict a
  failure mode, then actually reproducing it (via a targeted mock, a
  deliberately constructed mismatched-mtime scenario, or a zero-edges
  dataset) before fixing it, rather than fixing based on suspicion alone.
- Also specifically checked (found clean, no changes needed): HTML-escaping
  of all user/AD-derived data rendered via `innerHTML` throughout
  `AccessMapTemplate.html`; CSV-export quoting for embedded commas/quotes/
  newlines; the `-ExpandGroupsExclude` short-name-vs-full-name matching
  logic; `computeTopmostRoots`'s ancestor-chain walk; CIM session cleanup
  and DFS namespace traversal in `Get-FileServerShareInventory.ps1`.
- Re-ran the full existing suite (12 HTML/JS test files, 3 PowerShell test
  files) after every fix, plus real end-to-end runs at scale (a
  2,501-folder synthetic tree) across sequential, breadth-first, parallel,
  and parallel+breadth-first combined -- all four modes still produce
  identical, complete coverage.

---

## [0.2.2] - Breadth-first scan order option

### Added
- `Invoke-NTFSPermissionAudit.ps1`: new `-BreadthFirst` switch. Scans level
  by level (every folder at the current depth before any folder at the
  next depth) instead of the default depth-first order (one branch all
  the way down before backing up to its siblings). Implemented with a
  `Queue` instead of a `Stack` for the traversal frontier when set (both
  are O(1) per operation -- deliberately not a `List` with `RemoveAt(0)`,
  which would be quietly O(n) per removal on exactly the large scans this
  targets).
- Rationale: if a scan of a very large share is interrupted partway
  through (killed, times out, a reboot), depth-first leaves one
  fully-scanned branch and nothing else, while breadth-first leaves the
  top few levels of everything -- a far more useful partial result in
  most cases, and one the HTML tree view already displays well with no
  changes needed (a shallow-but-complete tree is indistinguishable from
  an intentionally `-MaxDepth`-limited run).

### Testing notes
- Built a real nested test directory tree and confirmed via `-Verbose`
  trace analysis (not just eyeballing it) that both modes visit the
  identical *set* of folders, breadth-first's depth sequence is strictly
  non-decreasing, depth-first's is a genuine zigzag, and all depth-1
  siblings are visited before any depth-2 folder under `-BreadthFirst`.
  Confirmed default-mode behavior (error counts, folders touched) is
  byte-for-byte unaffected by the refactor. Confirmed -- by re-running the
  full HTML test suite unmodified -- that scan order has zero effect on
  `Build-AccessMapHtml.ps1`'s output, since folder hierarchy there is
  reconstructed from path strings, never from CSV row order.

---

## [0.2.1] - Version-mismatch troubleshooting (no functional changes)

### Fixed
- No code changes in this release -- prompted by a real support case
  where a user's Summary view showed "0 objects could not be scanned"
  despite `Errors.log` containing 5 real entries. Reproduced the exact
  scenario synthetically and confirmed the parsing/display pipeline
  itself was correct; root cause was that only `AccessMapTemplate.html`
  had been re-shared recently, not the paired `Build-AccessMapHtml.ps1`
  containing the `Errors.log`-parsing feature -- an older copy of that
  script silently shows 0 (indistinguishable from "clean scan") rather
  than erroring.

### Changed
- Version bumped (all three scripts + README) specifically so the
  generated report's footer (`toolkit vX.X.X`) can be used as a quick
  sanity check that the version in front of you is the one you think it
  is.
- `README.md`: fixed remaining bare `Errors.log` references to note the
  actual `Errors_<timestamp>.log` naming; added the diagnostic sequence
  for a suspicious "0 errors" result (check the footer version, check the
  log file actually exists where you pointed `-InputFolder`, check the
  HTML was regenerated after the run that produced the errors); combined
  the existing file-colocation requirement with new "keep all three
  scripts as a matched set" guidance.

---

## [0.2.0] - Interactive access map redesign, reliability fixes, PowerShell 7 support

### Fixed
- **PowerShell 7 compatibility**: `[System.IO.Directory]::GetAccessControl`
  (used to read ACLs) only exists in full .NET Framework (PS 5.1); PS7 runs
  on .NET Core, where the same functionality moved to extension methods on
  `DirectoryInfo`/`FileInfo`. `Get-ObjectAcl` now branches on
  `$PSVersionTable.PSEdition` so the script works correctly under both.
- **Owner-resolution crash under `Set-StrictMode`**: `DirectorySecurity`/
  `FileSecurity` has no public `.Owner` property (only `GetOwner(type)`);
  a broken fallback line was aborting entire scans whenever an owner SID
  couldn't be translated to a name (a common, non-exceptional case for
  orphaned/foreign SIDs). Replaced with a real three-level fallback
  (friendly name -> raw SID string -> logged placeholder) that cannot
  itself throw.
- **Access-map "hub explosion"**: the relationship graph would walk
  through a shared Group's *own* other access edges, letting one broadly-
  permissioned group bridge two unrelated parts of the tree into one
  tangled view. Fixed twice, progressively: first by restricting
  non-centered Groups/Unresolved/Well-known identities to revealing only
  their direct reach (membership only) unless they're the actual
  selection; then generalized from identity *type* to actual *fan-out*,
  after a screenshot showed a User-typed admin account (`Administrator`)
  with a large footprint causing the identical problem untouched by the
  type-only rule.
- **Color collision**: broken-inheritance folders were colored identically
  to the actual graph center, creating a "second center" illusion in
  screenshots. Folders now always render their normal color; the existing
  small flag-dot indicator (shared with disabled/dormant identity flags)
  marks broken inheritance without hijacking the node's main color.
- **Table filter losing keyboard focus on every keystroke**: the filter
  `<input>` was being destroyed and recreated on every character typed.
  `renderTable()` now builds the input once and only updates rows/header/
  export-count afterward.

### Changed
- **Access map visualization redesigned from a relationship graph to a
  folder/subfolder tree** as the primary view, after feedback that
  depth-based relationship hops were the wrong model: a single folder has
  no meaningful "depth" to traverse, identity views rendered in a
  fixed-size canvas rather than expanding to a readable size, and higher
  depths kept reaching back through the share root into relationships
  outside the selected identity's own access. The tree mirrors Explorer,
  with each subfolder's own children branching from it specifically
  (never pooled with a sibling's); depth (1-5, Full) now means levels of
  subfolder nesting to auto-expand, matching the requested A-B/A-B-1
  semantics exactly. Structurally eliminates the "hub explosion" class of
  bugs, since a tree never walks through other identities at all.
- **The relationship graph brought back as a second "Graph" tab**
  alongside "Tree", after feedback that the picture view was still
  wanted for a different purpose (seeing direct relationships visually).
  Later given its own depth control (separate from the Tree's, since they
  mean different things), reusing the hub-safe multi-hop traversal logic
  above.
- **Duplicate/overlapping tree roots fixed**: a normal recursive audit
  records an ACE row for every folder in a branch (inherited ACEs
  captured per-folder), so an identity's "directly accessed folders"
  naturally includes both a parent and several of its own descendants --
  shown as a duplicated top-level root without correction. Added
  `computeTopmostRoots()` to keep only the topmost folder per branch.
- **`-SkipInheritedAcesInFolderReport` renamed to `-SkipInheritedAces`**
  (old name kept as a parameter alias) -- it always filtered both CSVs,
  not just the folder one, so the old name was misleading.
- **Summary view added**, consolidating scattered counts into one screen
  shown by default on open: identity breakdown by type, user account
  health (enabled/disabled/locked/dormant), an access-rights distribution
  donut chart, a plain-language "what each access level allows and how it
  could be misused" reference table, and a set of data-driven
  observations (broad default-group grants, broken inheritance, stale
  account access, orphaned SIDs, high Full-Control share) each mapped to
  specific, sourced normative guidance tagged by region -- **AU** (ACSC
  Essential Eight by maturity level, Australian Government ISM
  principles), **NZ** (specific NZISM control IDs), **US** (named NIST SP
  800-53 control IDs and CSF 2.0 subcategories), **Intl** (CIS Controls
  v8 safeguards) -- researched against current published wording rather
  than relied on from memory, and explicitly framed as a heuristic
  starting point for a security/compliance conversation, not a certified
  assessment. The header's separate stats line was removed as pure
  duplication once this existed.
- **`Errors.log` now ingested into the access map** as "folders that
  could not be scanned", parsed and categorized (access denied / path-
  platform limitation / other), exportable to CSV -- previously these
  objects were invisible blind spots with no ACL data to display anywhere.
- **Output files timestamped** (`FolderPermissions_<timestamp>.csv`, etc.)
  across all three scripts, with `-Force` required to overwrite an exact
  collision -- re-running into a shared `-OutputFolder` no longer
  silently clobbers a previous run.
- **`Build-AccessMapHtml.ps1` output-path handling**: accepts a full file
  path, an empty directory (auto-names inside it), or errors clearly on a
  non-empty directory rather than guessing a filename into it.
- **DFS discovery reworked for restricted-access environments**: new
  `-DfsPath` on `Get-FileServerShareInventory.ps1` resolves a known DFS
  path to its physical target via the client-side `NetDfsGetClientInfo`
  API -- no DFS admin rights or RSAT module required, unlike
  `-DfsNamespace`'s full tree enumeration (kept as an optional
  higher-privilege bonus).
- `ADIdentityDetails.csv` / access map: added `WhenChanged` as a more
  consistently-available fallback when `LastLogonTimestampApprox` is
  blank or stale.
- Added `LICENSE` (MIT) and `Version`/`$ScriptVersion` metadata (shown in
  each script's startup banner and, for the access map, in the generated
  report's own footer) to all three scripts.
- Added `Manual-DFS-Verification.md`: a checklist for hand-verifying DFS
  topology when no tooling -- not even `-DfsPath` -- can query it at all.

### Testing notes
- Each fix above was verified with a purpose-built reproduction before
  being called fixed, not just patched and assumed correct -- notably the
  hub-explosion fix was tested against a synthetic dataset mirroring the
  exact reported scenario (a shared group with access to two unrelated
  folders) both before and after the fan-out generalization, and the tree
  redesign was tested against a dataset matching the requested A-B/A-B-1
  branching example precisely, including that depths 4/5/Full correctly
  plateau rather than double-counting.
- Retired four test files that exercised mechanisms intentionally removed
  in the tree redesign (drag/zoom/pan interaction, BFS hub-restriction on
  the old single graph) -- expected, not a regression.
- Test suite grew to 10 files covering the tree, the reintroduced graph
  (including its own depth control and the hub-safe engine end-to-end),
  the summary view (including specific AU/NZ/US control-ID citations,
  not just framework names), focus retention, and scale (400+ identities).

---

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
