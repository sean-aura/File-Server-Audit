# Manual DFS Verification Checklist

Use this when you have **no way to query DFS at all** -- not the `DFSN`
module, not even the client-referral trick in `Get-FileServerShareInventory.ps1
-DfsPath` (it can fail too: DFS client service disabled/blocked by policy,
the path unreachable from where you're running it, firewall blocking the RPC
call, etc.) -- and you need to hand-verify things instead.

It's organized by what you're trying to establish, cheapest/least-privileged
methods first. The last section is a deliberately honest list of things that
**cannot** be self-served -- they need someone with server or DFS-management
access, and the right move there is to ask, not to work around it.

---

## 1. Work out what DFS paths are actually in use

You can't enumerate the namespace, so get the list a different way -- from
people and config that already reference it, rather than from DFS itself:

- **Ask application/business owners or end users** which UNC path they map
  drives to, put in shortcuts, or reference in scripts/config for the
  systems you're auditing. This is usually faster and more accurate than
  discovering it than any tooling would be anyway, since it tells you what's
  *actually used*, not just what's configured.
- **Check Group Policy drive mappings.** GPMC read access is a *different*
  permission from DFS namespace config read access -- you may well be able
  to browse Group Policy Preferences > Drive Maps (or logon-script GPOs)
  even with zero DFS rights, and find `\\domain\namespace\...` targets
  there.
- **Check logon scripts.** SYSVOL is readable domain-wide by default; look
  for `net use` statements referencing DFS paths.
- **Check a sample workstation.** `net use` or "This PC" in Explorer shows
  currently mapped drives and their UNC paths.
- **Check existing documentation** -- CMDB, runbooks, an internal wiki. Even
  an out-of-date document usually names the namespace and top-level folders
  correctly even if the physical targets behind them have since changed.

## 2. Resolve one specific DFS path to its physical target -- no admin tools needed

This is the single most useful trick here, and it needs **no special
rights** -- it works for any account that can browse the path at all,
because it's the exact same underlying mechanism our `-DfsPath` option uses,
just exposed through the Explorer GUI instead of a script:

1. In Windows Explorer, navigate to the DFS path (e.g.
   `\\contoso.com\Public\Finance`).
2. Right-click the folder > **Properties**.
3. Click the **DFS** tab. (This tab is only present if the folder is
   actually part of a DFS namespace -- if it's missing, that itself tells
   you the path isn't DFS-enabled.)
4. This lists every **Folder Target** (physical `\\server\share`) with a
   **Status** column (Online/Offline). Record what's shown.

Caveat: this dialog doesn't always make it obvious *which* target your
current session is actually using when more than one is Online (that
depends on Windows version/DFS client settings) -- for that, go to step 3.

## 3. Determine which physical server your session is *currently* talking to

1. Open (or list a file inside) the DFS path at least once in your current
   session, so Windows actually establishes the underlying connection --
   just having the folder open in Explorer may not be enough to force it.
2. Run `Get-SmbConnection` in PowerShell (part of the in-box `SmbShare`
   module -- no RSAT needed, works on any modern Windows client or server).
   This lists active SMB sessions, and for a resolved DFS referral it shows
   the real `ServerName` your session is talking to for that `ShareName`.
   Cross-reference the `ShareName` against the Folder Targets you recorded
   in step 2 to know which physical target is live for you right now.
3. Optionally, `Test-NetConnection <server> -Port 445` against each
   candidate target server rules out anything clearly unreachable -- though
   "reachable" isn't the same as "currently the one referred to you."

## 4. Cross-check that the active and standby nodes actually agree

Once you have both physical paths (from step 2), this is a genuinely useful
sanity check you *can* do yourself with the other scripts in this toolkit,
without any DFS access at all:

- Run `Invoke-NTFSPermissionAudit.ps1` against **both** physical UNC paths
  separately (one run per node) and diff the two `FolderPermissions.csv`
  outputs. Any difference points to either a replication backlog or a real
  permissions drift between the nodes -- worth investigating before you
  treat "the DFS path" as a single reliable source of truth.
- As a quick spot-check, manually compare a handful of folders' Properties >
  Security > Advanced tab side-by-side on both servers.

## 5. Share-level permissions on each physical target

Share-level ACLs are a separate layer from NTFS permissions (see the main
README) and aren't visible from the DFS Properties dialog above. If
`Get-FileServerShareInventory.ps1 -ComputerName` doesn't work for you (no
`SmbShare` module locally, no CIM/WinRM connectivity to the server):

- Ask the file server admin to run `Get-SmbShareAccess -Name <ShareName>` on
  each physical server and send you the output -- it's one command, cheap
  to ask for even from someone who won't grant you standing access.
- If you have any interactive (even non-admin) logon to the server itself,
  Computer Management > Shared Folders > Shares is often viewable
  (read-only) even when you can't change anything there.

---

## What genuinely cannot be self-served -- ask the DFS/infrastructure team for these

Be upfront with yourself (and whoever's waiting on the audit) that these
need someone with server or DFS-management access; there's no end-user or
no-tools way around them, and pretending otherwise just produces false
confidence in the results:

- **Full enumeration of every folder in the namespace**, if you don't
  already know all the paths in use from step 1. Listing "everything
  configured in DFS" is inherently a management-tier operation.
- **DFS-R replication health / backlog status** between the active and
  standby nodes (`dfsrdiag replicationstate`, or the DFS Management
  console's Replication health report). If there's a backlog, whatever you
  scanned on one node may not yet match the other.
- **Confirmation of "designated active" vs. simple reachability**, if step 2
  showed more than one Online target and it isn't obvious which one is
  actually preferred (referral ordering / Active Directory site costing
  configuration).
- **Share-level ACLs**, if step 5's fallback doesn't apply to you either.

When you ask, you're asking for a handful of specific, fast, read-only
commands from someone who already has the access -- not for a standing grant
of DFS admin rights -- which is usually a much easier ask to get approved.
