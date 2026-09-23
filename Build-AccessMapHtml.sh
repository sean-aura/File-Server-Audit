#!/usr/bin/env bash
#
# Build-AccessMapHtml.sh -- offline Linux/macOS bash+awk port of
# Build-AccessMapHtml.ps1. Turns the CSVs from Invoke-NTFSPermissionAudit.ps1
# into the same AccessMap.html + AccessMap_data/ report the PowerShell script
# produces (see that script's own header comment for the full design and
# rationale -- this file only documents where it differs).
#
# Usage:
#   Build-AccessMapHtml.sh -i INPUT_FOLDER [-o OUTPUT_FOLDER] [-m MAX_EDGES] [-f]
#
#   -i, --input-folder DIR    Output folder from a previous
#                              Invoke-NTFSPermissionAudit.ps1 run. Required.
#   -o, --output-folder DIR   Where to write AccessMap.html + AccessMap_data/.
#                              Defaults to a timestamped subfolder of
#                              INPUT_FOLDER, matching the PowerShell version.
#   -m, --max-edges-per-node N   Tree fan-out cap before "+N more". Default 60.
#   -f, --force                Allow writing into a non-empty OUTPUT_FOLDER.
#   -h, --help                 Show this help and exit.
#
# Deliberately does NOT use `set -e` / `set -u` / `set -o pipefail` (per
# request) -- every command whose failure matters is checked explicitly
# instead, right where it runs.
#
# CSV parsing handles quoted fields with embedded commas, doubled ""
# quote-escaping, \r\n line endings, and a quoted field that legitimately
# contains a literal embedded newline (detected by counting `"` characters
# and treating an odd running total as "still inside a quoted field",
# buffering physical lines together until it closes -- see build.awk's main
# loop). The build's own summary output reports it when a multi-line record
# is reassembled, or when a file ends with an unterminated quote (dropped
# and counted the same way a truncated last line is).
#
# KNOWN DIFFERENCE from the PowerShell version (read this before relying on
# byte-identical output):
#   - identities[]/folders[] array ORDER can differ from a PowerShell-built
#     report for the same input (this script doesn't replicate the
#     PowerShell version's SID-sort seeding order). The DATA is equivalent
#     either way -- nothing in AccessMap.html depends on array order -- this
#     only means a byte-diff between a PowerShell-built and a bash-built
#     report from the same CSVs won't be empty, even though both are correct.

SCRIPT_VERSION="0.6.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

print_usage() {
    sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

INPUT_FOLDER=""
OUTPUT_FOLDER=""
MAX_EDGES_PER_NODE=60
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -i|--input-folder)
            INPUT_FOLDER="$2"; shift 2 ;;
        -o|--output-folder)
            OUTPUT_FOLDER="$2"; shift 2 ;;
        -m|--max-edges-per-node)
            MAX_EDGES_PER_NODE="$2"; shift 2 ;;
        -f|--force)
            FORCE=1; shift ;;
        -h|--help)
            print_usage; exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            print_usage
            exit 1 ;;
    esac
done

if [ -z "$INPUT_FOLDER" ]; then
    echo "ERROR: -i/--input-folder is required." >&2
    print_usage
    exit 1
fi
if [ ! -d "$INPUT_FOLDER" ]; then
    echo "ERROR: '$INPUT_FOLDER' is not a directory." >&2
    exit 1
fi
INPUT_FOLDER="$(cd "$INPUT_FOLDER" >/dev/null 2>&1 && pwd)"
if [ -z "$INPUT_FOLDER" ]; then
    echo "ERROR: could not resolve -i/--input-folder to an absolute path." >&2
    exit 1
fi

AWK_BIN="awk"
if ! command -v awk >/dev/null 2>&1; then
    echo "ERROR: no 'awk' found on PATH. This script needs a standard awk (gawk, mawk, or macOS/BSD awk all work)." >&2
    exit 1
fi

# ---- Find the latest run's CSVs by the timestamp embedded in their filenames ----
# (same convention as Invoke-NTFSPermissionAudit.ps1's own output: NAME_yyyyMMdd_HHmmss.csv)

find_latest_run_file() {
    # $1 = filename prefix (e.g. "IdentityPermissions"); prints the chosen
    # path on stdout, or nothing if none found. Warns on stderr if more than
    # one run's files are present.
    local prefix="$1"
    local candidates=()
    local f
    for f in "$INPUT_FOLDER/${prefix}"_*.csv; do
        [ -f "$f" ] && candidates+=("$f")
    done
    if [ "${#candidates[@]}" -eq 0 ]; then
        if [ -f "$INPUT_FOLDER/${prefix}.csv" ]; then
            printf '%s\n' "$INPUT_FOLDER/${prefix}.csv"
        fi
        return 0
    fi
    if [ "${#candidates[@]}" -gt 1 ]; then
        echo "WARNING: multiple ${prefix}_*.csv files found in '$INPUT_FOLDER' (output from more than one audit run?). Using the most recent by run timestamp. Point -i at a folder containing just the run you want if this isn't what you intended." >&2
    fi
    # Fixed-width yyyyMMdd_HHmmss timestamps sort correctly as plain strings.
    printf '%s\n' "${candidates[@]}" | sort -r | head -n 1
}

IDENTITY_PERMS_PATH="$(find_latest_run_file 'IdentityPermissions')"
if [ -z "$IDENTITY_PERMS_PATH" ]; then
    echo "ERROR: IdentityPermissions*.csv not found in '$INPUT_FOLDER'. Run Invoke-NTFSPermissionAudit.ps1 first." >&2
    exit 1
fi
AD_DETAILS_PATH="$(find_latest_run_file 'ADIdentityDetails')"
if [ -z "$AD_DETAILS_PATH" ]; then
    echo "WARNING: No ADIdentityDetails*.csv found in '$INPUT_FOLDER'. Identity nodes will show name/type only (no department/manager/account-state info)." >&2
fi

ERRORS_LOG_PATH=""
errors_candidates=()
for f in "$INPUT_FOLDER"/Errors_*.log; do
    [ -f "$f" ] && errors_candidates+=("$f")
done
if [ "${#errors_candidates[@]}" -eq 0 ]; then
    if [ -f "$INPUT_FOLDER/Errors.log" ]; then ERRORS_LOG_PATH="$INPUT_FOLDER/Errors.log"; fi
elif [ "${#errors_candidates[@]}" -eq 1 ]; then
    ERRORS_LOG_PATH="${errors_candidates[0]}"
else
    echo "WARNING: multiple Errors_*.log files found in '$INPUT_FOLDER' (output from more than one audit run?). Using the most recent by run timestamp." >&2
    ERRORS_LOG_PATH="$(printf '%s\n' "${errors_candidates[@]}" | sort -r | head -n 1)"
fi

RUN_TIMESTAMP=""
if [[ "$IDENTITY_PERMS_PATH" =~ _([0-9]{8}_[0-9]{6})\.csv$ ]]; then
    RUN_TIMESTAMP="${BASH_REMATCH[1]}"
else
    RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
fi

SCAN_COMPLETE="true"
if [[ "$IDENTITY_PERMS_PATH" =~ _([0-9]{8}_[0-9]{6})\.csv$ ]]; then
    if [ ! -f "$INPUT_FOLDER/Completed_${RUN_TIMESTAMP}.marker" ]; then
        SCAN_COMPLETE="false"
        echo "WARNING: No Completed_${RUN_TIMESTAMP}.marker found -- this run appears to have been interrupted before finishing. The report will say so and show everything that WAS captured." >&2
    fi
fi

# ---- Resolve OUTPUT_FOLDER (folder-based output, same semantics as -OutputFolder in the PS version) ----

if [ -z "$OUTPUT_FOLDER" ]; then
    OUTPUT_FOLDER="$INPUT_FOLDER/AccessMap_${RUN_TIMESTAMP}"
fi
if [ -e "$OUTPUT_FOLDER" ]; then
    if [ ! -d "$OUTPUT_FOLDER" ]; then
        echo "ERROR: '$OUTPUT_FOLDER' already exists and is a file, not a folder." >&2
        exit 1
    fi
    existing_count="$(ls -A "$OUTPUT_FOLDER" 2>/dev/null | wc -l)"
    if [ "$existing_count" -gt 0 ] && [ "$FORCE" -ne 1 ]; then
        echo "ERROR: '$OUTPUT_FOLDER' is an existing, non-empty folder. Re-run with -f/--force to write into it anyway, or point -o/--output-folder at a different/empty location." >&2
        exit 1
    fi
else
    mkdir -p "$OUTPUT_FOLDER"
    if [ $? -ne 0 ]; then
        echo "ERROR: could not create '$OUTPUT_FOLDER'." >&2
        exit 1
    fi
fi
OUTPUT_FOLDER="$(cd "$OUTPUT_FOLDER" >/dev/null 2>&1 && pwd)"
DATA_DIR_NAME="AccessMap_data"
DATA_DIR="$OUTPUT_FOLDER/$DATA_DIR_NAME"
mkdir -p "$DATA_DIR"
if [ $? -ne 0 ]; then
    echo "ERROR: could not create '$DATA_DIR'." >&2
    exit 1
fi

TEMPLATE_PATH="$SCRIPT_DIR/AccessMapTemplate.html"
if [ ! -f "$TEMPLATE_PATH" ]; then
    echo "ERROR: template file not found: '$TEMPLATE_PATH' (expected alongside this script)." >&2
    exit 1
fi

echo "Build-AccessMapHtml.sh v$SCRIPT_VERSION"
echo "Reading $IDENTITY_PERMS_PATH ..."
if [ -n "$AD_DETAILS_PATH" ]; then echo "Reading $AD_DETAILS_PATH ..."; fi
if [ -n "$ERRORS_LOG_PATH" ]; then echo "Reading $ERRORS_LOG_PATH ..."; fi

# ---- Truncated-last-line detection (a process killed mid-write can leave the last CSV line cut off) ----

TRUNCATED_ROWS_DROPPED=0
LAST_BYTE_IS_NEWLINE="$(tail -c1 "$IDENTITY_PERMS_PATH" | wc -l)"
USE_STDIN=0
if [ "$LAST_BYTE_IS_NEWLINE" -eq 0 ]; then
    echo "WARNING: '$IDENTITY_PERMS_PATH' doesn't end with a newline -- looks like the file was truncated mid-write (a killed/crashed run). Dropping that one incomplete last row; everything else in the file is unaffected." >&2
    TRUNCATED_ROWS_DROPPED=1
    USE_STDIN=1
fi

TMPDIR_WORK="$(mktemp -d 2>/dev/null)"
if [ -z "$TMPDIR_WORK" ] || [ ! -d "$TMPDIR_WORK" ]; then
    echo "ERROR: could not create a temporary working directory (mktemp -d failed)." >&2
    exit 1
fi
cleanup() { rm -rf "$TMPDIR_WORK"; }
trap cleanup EXIT

AWK_PROG="$SCRIPT_DIR/build.awk"
if [ ! -f "$AWK_PROG" ]; then
    echo "ERROR: build.awk not found alongside this script at '$AWK_PROG'." >&2
    exit 1
fi

GENERATED_AT="$(date '+%Y-%m-%d %H:%M:%S')"

if [ "$USE_STDIN" -eq 1 ]; then
    sed '$d' "$IDENTITY_PERMS_PATH" | "$AWK_BIN" \
        -v adpath="$AD_DETAILS_PATH" -v errpath="$ERRORS_LOG_PATH" \
        -v tmpdir="$TMPDIR_WORK" -v datadir="$DATA_DIR" \
        -v generatedat="$GENERATED_AT" -v srcfolder="$INPUT_FOLDER" \
        -v toolkitver="$SCRIPT_VERSION" -v scancomplete="$SCAN_COMPLETE" \
        -v truncdropped="$TRUNCATED_ROWS_DROPPED" -v maxedges="$MAX_EDGES_PER_NODE" \
        -f "$AWK_PROG"
    AWK_STATUS=$?
else
    "$AWK_BIN" \
        -v adpath="$AD_DETAILS_PATH" -v errpath="$ERRORS_LOG_PATH" \
        -v tmpdir="$TMPDIR_WORK" -v datadir="$DATA_DIR" \
        -v generatedat="$GENERATED_AT" -v srcfolder="$INPUT_FOLDER" \
        -v toolkitver="$SCRIPT_VERSION" -v scancomplete="$SCAN_COMPLETE" \
        -v truncdropped="$TRUNCATED_ROWS_DROPPED" -v maxedges="$MAX_EDGES_PER_NODE" \
        -f "$AWK_PROG" "$IDENTITY_PERMS_PATH"
    AWK_STATUS=$?
fi
if [ "$AWK_STATUS" -ne 0 ]; then
    echo "ERROR: build.awk failed (exit $AWK_STATUS)." >&2
    exit 1
fi

# ---- Finalize share_N.js from the prefix + raw-edges + suffix pieces awk wrote ----

SHARE_COUNT=0
if [ -f "$TMPDIR_WORK/share_count" ]; then
    SHARE_COUNT="$(cat "$TMPDIR_WORK/share_count")"
fi

n=0
while [ "$n" -lt "$SHARE_COUNT" ]; do
    prefix_file="$TMPDIR_WORK/share_${n}.prefix"
    raw_file="$TMPDIR_WORK/share_${n}.raw"
    out_file="$DATA_DIR/share_${n}.js"
    if [ ! -f "$raw_file" ]; then : > "$raw_file"; fi
    { cat "$prefix_file"; paste -sd, "$raw_file"; printf ']);\n'; } > "$out_file"
    if [ $? -ne 0 ]; then
        echo "ERROR: could not write '$out_file'." >&2
        exit 1
    fi
    n=$((n + 1))
done

cp "$TEMPLATE_PATH" "$OUTPUT_FOLDER/AccessMap.html"
if [ $? -ne 0 ]; then
    echo "ERROR: could not copy template to '$OUTPUT_FOLDER/AccessMap.html'." >&2
    exit 1
fi

echo "Access map written to $OUTPUT_FOLDER/AccessMap.html"
echo "($DATA_DIR_NAME/ holds its data -- keep the two together; copy/zip/email the whole '$OUTPUT_FOLDER' folder.)"
echo "Open AccessMap.html directly in a browser -- no server required."
