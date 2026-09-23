# build.awk -- the CSV -> AccessMap_data engine invoked by Build-AccessMapHtml.sh.
# See Build-AccessMapHtml.sh for the -v variables this expects (adpath, errpath,
# tmpdir, datadir, generatedat, srcfolder, toolkitver, scancomplete, truncdropped,
# maxedges). The main IdentityPermissions CSV is awk's own input (last positional
# arg, or piped via stdin when the caller had to drop a truncated last line first).

function to_bool(s) {
    return (s == "True" || s == "true" || s == "1") ? 1 : 0
}

# JSON string escaping: backslash first, then quote, then a couple of control
# characters this data could in principle carry (tab; stray CR from a
# Windows-authored file). Order matters -- backslash must be escaped before
# the escapes we just introduced get re-escaped.
function json_escape(s,    r) {
    r = s
    gsub(/\\/, "\\\\", r)
    gsub(/"/, "\\\"", r)
    gsub(/\t/, "\\t", r)
    gsub(/\r/, "", r)
    return r
}
function json_str(s) { return "\"" json_escape(s) "\"" }
# Empty string -> JSON null (matches the PowerShell version's $null for a
# field that was never populated), otherwise a quoted/escaped string.
function json_val(s) { return (s == "") ? "null" : json_str(s) }
# Same null-when-empty rule, but for the three-way enabled/locked flags.
function json_tribool(s) { return (s == "") ? "null" : (to_bool(s) ? "true" : "false") }
# For the plain (non-boolean) AD-detail fields: PowerShell's Get-OrAdd-Identity
# nulls these based on whether an AD detail RECORD exists at all for this
# identity, not on whether this one field happens to be blank -- an existing
# record with a blank attribute serializes as "" there, not null. Both are
# falsy in JS either way (functionally inert either way), but this keeps the
# two implementations' output semantically aligned rather than just
# "equivalent in practice".
function json_detail(idx, val) { return (idx in id_hasdetail) ? json_str(val) : "null" }

# Turns a US(\x1f)-joined list of plain integers back into a JSON array body
# (no brackets). Used for shareKeys-as-indices... actually shareKeys are
# strings (see json_str_list); this one is for integer lists (members,
# broadPrincipalGrants.folderIdxs).
function json_int_list(s,    n, a, i, out) {
    if (s == "") return ""
    n = split(s, a, US)
    out = a[1]
    for (i = 2; i <= n; i++) out = out "," a[i]
    return out
}
function json_str_list(s,    n, a, i, out) {
    if (s == "") return ""
    n = split(s, a, US)
    out = json_str(a[1])
    for (i = 2; i <= n; i++) out = out "," json_str(a[i])
    return out
}

# Some rows can carry a Windows extended-length path prefix (\\?\UNC\ for a
# network path, \\?\ for a local drive path) instead of the normal form --
# .NET's own long-path handling can independently decide to hand back a
# prefixed child path based on the CHILD's own resulting length, even when
# its parent's path was short enough not to need one (a real bug in
# Invoke-NTFSPermissionAudit.ps1's own un-prefixing logic, fixed there too,
# but existing CSVs captured before that fix still have it baked in and
# can't be re-scanned just to pick up the fix). Left alone, this breaks
# everything that depends on paths being in one consistent form: two spans
# of the very same folder tree end up looking like different addressing
# schemes, so a deep folder's computed parent path no longer string-matches
# its own ancestor (fracturing the tree exactly at the depth where the
# prefix kicks in) and its share key comes out as "\\?\UNC" for every prefixed
# folder regardless of which real share it's actually in. Normalizing every
# path to the same plain form, once, here, fixes both at the root.
function normalize_path(p) {
    if (substr(p, 1, 8) == "\\\\?\\UNC\\") return "\\\\" substr(p, 9)
    if (substr(p, 1, 4) == "\\\\?\\") return substr(p, 5)
    return p
}

# A folder's share is its first two non-empty \-separated path segments
# (\\server\share) -- same convention AccessMapTemplate.html's own
# buildFolderTree() uses to find share roots, and what Build-AccessMapHtml.ps1
# uses too.
function get_share_key(path,    n, parts, i, cnt, result) {
    n = split(path, parts, "\\")
    cnt = 0
    result = ""
    for (i = 1; i <= n; i++) {
        if (parts[i] != "") {
            cnt++
            if (cnt == 1) result = parts[i]
            else if (cnt == 2) { result = result "\\" parts[i]; break }
        }
    }
    if (cnt < 2) return path
    # Only prepend the UNC "\\" when the path itself actually had one -- for
    # a locally-rooted audit (a plain C:\... path, no UNC prefix at all),
    # unconditionally prepending it fabricated a share key ("\\D:\Shares")
    # that could never match any of that path's own real ancestors, which
    # broke AccessMapTemplate.html's client-side tree/breadcrumb logic for
    # any dataset scanned from a local path rather than a UNC one.
    if (substr(path, 1, 2) == "\\\\") return "\\\\" result
    return result
}

# Quote-aware CSV line splitter. Fast path (no quote char at all -> plain
# split(",")) covers the overwhelming majority of rows; the character-by-
# character state machine only runs on rows that actually contain a `"`
# (a quoted field, almost always because it embeds a comma -- RightsDetail
# is the common case). KNOWN LIMITATION vs. the PowerShell version's
# streaming parser: a literal embedded NEWLINE inside a quoted field is not
# supported here (this tool's own columns -- paths, names, rights text --
# don't carry free-form multi-line content, so this hasn't been a problem
# in practice, but it's a real, deliberate difference worth knowing about).
function csv_split(line, arr,    n, i, len, ch, field, in_quotes) {
    if (index(line, "\"") == 0) return split(line, arr, ",")
    n = 0
    field = ""
    in_quotes = 0
    i = 1
    len = length(line)
    while (i <= len) {
        ch = substr(line, i, 1)
        if (in_quotes) {
            if (ch == "\"") {
                if (substr(line, i + 1, 1) == "\"") { field = field "\""; i += 2 }
                else { in_quotes = 0; i++ }
            } else { field = field ch; i++ }
        } else {
            if (ch == "\"") { in_quotes = 1; i++ }
            else if (ch == ",") { n++; arr[n] = field; field = ""; i++ }
            else { field = field ch; i++ }
        }
    }
    n++
    arr[n] = field
    return n
}

function get_or_add_identity(sid, name, type,    key, idx) {
    key = (sid != "") ? ("sid:" sid) : ("name:" name)
    if (key in id_lookup) return id_lookup[key]
    idx = id_count++
    id_lookup[key] = idx
    id_sid[idx] = sid
    id_name[idx] = name
    id_type[idx] = type
    id_edgecount[idx] = 0
    if (name != "") id_name_lookup[tolower(name)] = idx
    if (sid != "" && (sid in ad_seen)) {
        id_hasdetail[idx] = 1
        id_title[idx] = ad_title[sid]; id_dept[idx] = ad_dept[sid]; id_manager[idx] = ad_manager[sid]
        id_email[idx] = ad_email[sid]; id_enabled[idx] = ad_enabled[sid]; id_locked[idx] = ad_locked[sid]
        id_lastlogon[idx] = ad_lastlogon[sid]; id_pwdset[idx] = ad_pwdset[sid]; id_expires[idx] = ad_expires[sid]
        id_created[idx] = ad_created[sid]; id_changed[idx] = ad_changed[sid]; id_groupscope[idx] = ad_groupscope[sid]
        id_membercount[idx] = ad_membercount[sid]; id_managedby[idx] = ad_managedby[sid]; id_notes[idx] = ad_notes[sid]
    }
    return idx
}

function get_or_add_folder(path,    idx, shareKey) {
    if (path in folder_lookup) return folder_lookup[path]
    idx = folder_count++
    folder_lookup[path] = idx
    folder_path[idx] = path
    folder_broken[idx] = 0
    shareKey = get_share_key(path)
    folder_share[idx] = shareKey
    if (!(shareKey in share_seen)) {
        share_seen[shareKey] = 1
        share_order[share_count] = shareKey
        share_tmpfile[shareKey] = tmpdir "/share_" share_count ".raw"
        share_folder_count[shareKey] = 0
        share_edge_count[shareKey] = 0
        share_count++
    }
    share_folder_count[shareKey]++
    return idx
}

function load_ad_details(path,    line, first, n, i, af, sid) {
    if (path == "") return
    first = 1
    while ((getline line < path) > 0) {
        if (first) {
            first = 0
            n = csv_split(line, adhdr)
            for (i = 1; i <= n; i++) adcolidx[adhdr[i]] = i
            continue
        }
        n = csv_split(line, af)
        sid = af[adcolidx["IdentitySid"]]
        if (sid == "") continue
        ad_seen[sid] = 1
        ad_name[sid] = af[adcolidx["IdentityName"]]
        ad_type[sid] = af[adcolidx["IdentityType"]]
        ad_title[sid] = af[adcolidx["Title"]]
        ad_dept[sid] = af[adcolidx["Department"]]
        ad_manager[sid] = af[adcolidx["Manager"]]
        ad_email[sid] = af[adcolidx["EmailAddress"]]
        ad_enabled[sid] = af[adcolidx["Enabled"]]
        ad_locked[sid] = af[adcolidx["LockedOut"]]
        ad_lastlogon[sid] = af[adcolidx["LastLogonTimestampApprox"]]
        ad_pwdset[sid] = af[adcolidx["PasswordLastSet"]]
        ad_expires[sid] = af[adcolidx["AccountExpirationDate"]]
        ad_created[sid] = af[adcolidx["WhenCreated"]]
        ad_changed[sid] = af[adcolidx["WhenChanged"]]
        ad_groupscope[sid] = af[adcolidx["GroupScope"]]
        ad_membercount[sid] = af[adcolidx["DirectMemberCount"]]
        ad_managedby[sid] = af[adcolidx["ManagedBy"]]
        ad_notes[sid] = af[adcolidx["LookupNotes"]]
    }
    close(path)
}

function load_errors(path,    line, closeb, rest, sep, ts, epath, msg, category, k) {
    if (path == "") return
    while ((getline line < path) > 0) {
        if (line == "") continue
        ts = ""; epath = ""; msg = line
        if (substr(line, 1, 1) == "[") {
            closeb = index(line, "]")
            if (closeb > 0) {
                rest = substr(line, closeb + 2)
                sep = index(rest, " :: ")
                if (sep > 0) {
                    ts = substr(line, 2, closeb - 2)
                    epath = substr(rest, 1, sep - 1)
                    msg = substr(rest, sep + 4)
                }
            }
        }
        if (msg ~ /Access denied/) category = "Access denied"
        else if (msg ~ /PathTooLong/ || msg ~ /too long/ || msg ~ /not supported.*platform/) category = "Path/platform limitation"
        else category = "Other"

        if (epath == "") {
            scanerr_count++
            se_ts[scanerr_count] = ts; se_path[scanerr_count] = epath; se_msg[scanerr_count] = msg; se_cat[scanerr_count] = category
        } else if (epath in se_pathidx) {
            k = se_pathidx[epath]
            se_ts[k] = ts; se_msg[k] = msg; se_cat[k] = category
            dedup_count++
        } else {
            scanerr_count++
            se_ts[scanerr_count] = ts; se_path[scanerr_count] = epath; se_msg[scanerr_count] = msg; se_cat[scanerr_count] = category
            se_pathidx[epath] = scanerr_count
        }
    }
    close(path)
}

BEGIN {
    FS = ""   # unused; we split manually via csv_split
    US = sprintf("%c", 31)   # ASCII unit separator -- internal list delimiter that
                              # can't collide with real data (share names, SIDs, etc.)

    rights_code_map["Full Control"] = 0
    rights_code_map["Modify"] = 1
    rights_code_map["Read & Execute"] = 2
    rights_code_map["Read"] = 3
    rights_code_map["Write"] = 4
    rights_code_map["Special"] = 5

    broad_principal_names["everyone"] = 1
    broad_principal_names["authenticated users"] = 1
    broad_principal_names["domain users"] = 1
    broad_principal_names["users"] = 1

    id_count = 0
    folder_count = 0
    share_count = 0
    total_edges = 0
    file_rows_excluded = 0
    broken_folder_count = 0
    broad_folder_count = 0
    scanerr_count = 0
    dedup_count = 0

    if (adpath != "") {
        load_ad_details(adpath)
        for (sid in ad_seen) get_or_add_identity(sid, ad_name[sid], ad_type[sid])
    }
    if (errpath != "") load_errors(errpath)
}

{
    # Multi-physical-line CSV record handling: a quoted field can legitimately
    # contain a literal newline (Export-Csv will write one across two-or-more
    # physical lines with the field still wrapped in one pair of quotes).
    # Detect this the standard way -- an ODD number of `"` characters in the
    # record built so far means a quoted field is still open -- and keep
    # buffering physical lines (joined back with a real newline, so the
    # embedded newline survives inside the field's value) until the count
    # comes back even. A CR left over from a \r\n-authored file is stripped
    # from every physical line first, unconditionally, so it can never end up
    # stuck onto the last field of a row regardless of column order.
    raw = $0
    sub(/\r$/, "", raw)
    pending = (pending == "") ? raw : (pending "\n" raw)
    qc = gsub(/"/, "\"", pending)
    if (qc % 2 != 0) next
    line = pending
    pending = ""
    if (index(line, "\n") > 0) multiline_record_count++

    if (!header_done) {
        header_done = 1
        ncols = csv_split(line, hdr)
        for (i = 1; i <= ncols; i++) colidx[hdr[i]] = i
        data_row_count = 0
        next
    }
    data_row_count++

    n = csv_split(line, f)
    objectType = f[colidx["ObjectType"]]
    if (objectType == "File") { file_rows_excluded++; next }

    identityName = f[colidx["IdentityName"]]
    identitySid  = f[colidx["IdentitySid"]]
    identityType = f[colidx["IdentityType"]]
    grantedVia   = f[colidx["GrantedViaGroup"]]
    path         = normalize_path(f[colidx["Path"]])
    accessControlType  = f[colidx["AccessControlType"]]
    rightsSummary      = f[colidx["RightsSummary"]]
    isInheritedAce     = f[colidx["IsInheritedAce"]]
    inheritanceBroken  = f[colidx["InheritanceBrokenHere"]]

    identityIdx = get_or_add_identity(identitySid, identityName, identityType)
    folderIdx   = get_or_add_folder(path)
    shareKey    = folder_share[folderIdx]

    brokenBool = to_bool(inheritanceBroken)
    if (brokenBool && !folder_broken[folderIdx]) {
        folder_broken[folderIdx] = 1
        broken_folder_count++
    }

    viaIdx = -1
    if (grantedVia != "") {
        vkey = tolower(grantedVia)
        if (vkey in id_name_lookup) viaIdx = id_name_lookup[vkey]
    }
    if (viaIdx >= 0) {
        mkey = viaIdx SUBSEP identityIdx
        if (!(mkey in group_member_seen)) {
            group_member_seen[mkey] = 1
            group_members[viaIdx] = (group_members[viaIdx] == "") ? identityIdx : group_members[viaIdx] US identityIdx
        }
    }

    rightsCode = (rightsSummary in rights_code_map) ? rights_code_map[rightsSummary] : 5
    isDeny = (accessControlType == "Deny") ? 1 : 0
    isInh  = to_bool(isInheritedAce)

    print "[" folderIdx "," identityIdx "," rightsCode "," isInh "," brokenBool "," isDeny "," viaIdx "]" > share_tmpfile[shareKey]

    total_edges++
    share_edge_count[shareKey]++
    rights_dist[rightsCode]++

    id_edgecount[identityIdx]++
    skey2 = identityIdx SUBSEP shareKey
    if (!(skey2 in id_share_seen)) {
        id_share_seen[skey2] = 1
        id_sharekeys[identityIdx] = (id_sharekeys[identityIdx] == "") ? shareKey : id_sharekeys[identityIdx] US shareKey
    }

    if (!isDeny && (rightsCode == 0 || rightsCode == 1)) {
        shortName = identityName
        while ((p2 = index(shortName, "\\")) > 0) shortName = substr(shortName, p2 + 1)
        if (shortName != "" && (tolower(shortName) in broad_principal_names)) {
            if (!(folderIdx in broad_folder_seen)) {
                broad_folder_seen[folderIdx] = 1
                broad_folder_count++
                broad_folder_list = (broad_folder_list == "") ? folderIdx : broad_folder_list US folderIdx
            }
        }
    }
}

END {
    if (pending != "") {
        # File ended with an unterminated quoted field -- either a genuinely
        # malformed CSV, or (far more likely) the same "process was killed
        # mid-write" scenario the bash driver's own trailing-newline check
        # already catches, just caught here instead because the cut point
        # happened to land inside a quoted field. Same treatment either way:
        # drop that one incomplete row and count it.
        print "WARNING: the CSV ended with an unterminated quoted field -- the last row was incomplete (truncated mid-write, or malformed) and has been dropped." > "/dev/stderr"
        unterminated_at_eof = 1
    }
    if (dedup_count > 0) {
        printf "%d duplicate error entry/entries (same path logged more than once) were collapsed to the most recent attempt.\n", dedup_count
    }

    # ---- manifest.js ----
    m = "const ACCESS_MAP_MANIFEST = {"
    m = m "\"identities\":["
    for (idx = 0; idx < id_count; idx++) {
        if (idx > 0) m = m ","
        m = m "{" \
            "\"sid\":" json_str(id_sid[idx]) "," \
            "\"name\":" json_str(id_name[idx]) "," \
            "\"type\":" json_str(id_type[idx]) "," \
            "\"title\":" json_detail(idx, id_title[idx]) "," \
            "\"dept\":" json_detail(idx, id_dept[idx]) "," \
            "\"manager\":" json_detail(idx, id_manager[idx]) "," \
            "\"email\":" json_detail(idx, id_email[idx]) "," \
            "\"enabled\":" json_tribool(id_enabled[idx]) "," \
            "\"locked\":" json_tribool(id_locked[idx]) "," \
            "\"lastLogon\":" json_detail(idx, id_lastlogon[idx]) "," \
            "\"pwdSet\":" json_detail(idx, id_pwdset[idx]) "," \
            "\"expires\":" json_detail(idx, id_expires[idx]) "," \
            "\"created\":" json_detail(idx, id_created[idx]) "," \
            "\"changed\":" json_detail(idx, id_changed[idx]) "," \
            "\"groupScope\":" json_detail(idx, id_groupscope[idx]) "," \
            "\"memberCount\":" json_detail(idx, id_membercount[idx]) "," \
            "\"managedBy\":" json_detail(idx, id_managedby[idx]) "," \
            "\"notes\":" json_detail(idx, id_notes[idx]) "," \
            "\"edgeCount\":" (id_edgecount[idx] + 0) "," \
            "\"shareKeys\":[" json_str_list(id_sharekeys[idx]) "]"
        if (group_members[idx] != "") m = m ",\"members\":[" json_int_list(group_members[idx]) "]"
        m = m "}"
    }
    m = m "],\"folders\":["
    for (idx = 0; idx < folder_count; idx++) {
        if (idx > 0) m = m ","
        m = m "{\"path\":" json_str(folder_path[idx]) ",\"broken\":" (folder_broken[idx] ? "true" : "false") ",\"share\":" json_str(folder_share[idx]) "}"
    }
    m = m "],\"shares\":["
    for (s = 0; s < share_count; s++) {
        key = share_order[s]
        if (s > 0) m = m ","
        m = m "{\"key\":" json_str(key) ",\"label\":" json_str(key) ",\"file\":\"share_" s ".js\",\"folderCount\":" (share_folder_count[key] + 0) ",\"edgeCount\":" (share_edge_count[key] + 0) "}"
    }
    m = m "]"
    m = m ",\"totalEdgeCount\":" (total_edges + 0)
    m = m ",\"rightsDistribution\":[" (rights_dist[0]+0) "," (rights_dist[1]+0) "," (rights_dist[2]+0) "," (rights_dist[3]+0) "," (rights_dist[4]+0) "," (rights_dist[5]+0) "]"
    m = m ",\"broadPrincipalGrants\":{\"folderCount\":" (broad_folder_count + 0) ",\"folderIdxs\":[" json_int_list(broad_folder_list) "]}"
    m = m ",\"maxEdgesPerNode\":" (maxedges + 0)
    m = m ",\"generatedAt\":" json_str(generatedat)
    m = m ",\"sourceFolder\":" json_str(srcfolder)
    m = m ",\"toolkitVersion\":" json_str(toolkitver)
    m = m ",\"scanErrors\":["
    for (k = 1; k <= scanerr_count; k++) {
        if (k > 1) m = m ","
        m = m "{\"Timestamp\":" json_val(se_ts[k]) ",\"Path\":" json_val(se_path[k]) ",\"Message\":" json_val(se_msg[k]) ",\"Category\":" json_val(se_cat[k]) "}"
    }
    m = m "]"
    m = m ",\"scanComplete\":" (scancomplete == "true" ? "true" : "false")
    # If the bash driver already dropped the file's last physical line
    # because it wasn't newline-terminated (truncdropped==1), an unterminated
    # quote still open at EOF here is very likely that SAME lost row (the
    # truncation just happened to land inside a quoted field spanning more
    # than one physical line, so trimming only the very last line wasn't
    # enough to make the remainder well-formed) -- don't count it a second
    # time. Only add for this reason when the file otherwise looked complete
    # (a distinct problem: a genuinely malformed/corrupted CSV, not a
    # mid-write kill).
    m = m ",\"truncatedRowsDropped\":" (truncdropped + (truncdropped == 0 ? unterminated_at_eof : 0) + 0)
    m = m "};"
    print m > (datadir "/manifest.js")
    close(datadir "/manifest.js")

    # ---- per-share prefix files (finalized/joined by the bash driver) ----
    for (s = 0; s < share_count; s++) {
        key = share_order[s]
        close(share_tmpfile[key])   # flush before the driver reads it back
        print "registerShareChunk(" json_str(key) ",[" > (tmpdir "/share_" s ".prefix")
        close(tmpdir "/share_" s ".prefix")
        if (share_edge_count[key] > 150000) {
            printf "WARNING: share %s has a large number of access entries (%d). That share's own AccessMap_data/share_%d.js may take a moment to fetch and the browser may feel sluggish once you open something in it, even though the rest of the report stays fast.\n", key, share_edge_count[key], s > "/dev/stderr"
        }
    }

    printf "Read %d permission row(s).   Identities: %d   Folders: %d   Shares: %d   Edges: %d   Broken-inheritance folders: %d\n", \
        data_row_count, id_count, folder_count, share_count, total_edges, broken_folder_count
    if (multiline_record_count > 0) {
        printf "%d row(s) had a quoted field containing a literal newline and were correctly reassembled across the physical lines they spanned.\n", multiline_record_count
    }
    if (file_rows_excluded > 0) {
        printf "%d file-level access row(s) from -IncludeFiles were excluded from this interactive map (folders/identities only).\n", file_rows_excluded
    }

    print share_count > (tmpdir "/share_count")
    close(tmpdir "/share_count")
}
