#!/usr/bin/env bash
# Generate Doxygen XML test fixtures from zkapputilslib's public API headers.
#
# Usage: scripts/make-fixtures.sh <zkapputilslib checkout> <output dir>
#
# Uses zkapputilslib's own docs/Doxyfile with the same per-language settings as
# its docs/c and docs/cpp Makefiles, except that XML_PROGRAMLISTING is off so
# the fixtures carry the API and its comments, not a copy of the header source,
# and paths are stripped so the output does not record where it was built.
set -euo pipefail
SRC=$(realpath "$1")
OUT=$(realpath -m "$2")
DOXYGEN=${DOXYGEN:-doxygen}

run() {  # <language> <header> <OPTIMIZE_OUTPUT_FOR_C>
    local lang=$1 header=$2 for_c=$3 tmp
    tmp=$(mktemp -d)
    printf '@INCLUDE = %s\nOUTPUT_DIRECTORY = %s\nSTRIP_FROM_PATH = %s/\nXML_PROGRAMLISTING = NO\nQUIET = YES\n' \
        "$SRC/docs/Doxyfile" "$OUT/$lang" "$SRC" > "$tmp/Doxyfile"
    rm -rf "${OUT:?}/${lang:?}"
    mkdir -p "$OUT/$lang"
    (cd "$tmp" && DOXY_INPUT="$SRC/$header" DOXY_OPTIMIZE_OUTPUT_FOR_C=$for_c "$DOXYGEN" Doxyfile)
    rm -rf "${tmp:?}"
    # Keep only what the extractor reads: the index and the compound files. The
    # schemas, directory pages and Doxyfile.xml add nothing and record local paths.
    find "$OUT/$lang/xml" -type f ! -name index.xml ! -name 'struct*.xml' ! -name 'class*.xml' \
        ! -name 'namespace*.xml' ! -name 'group__*.xml' ! -name '*_8h.xml' -delete
}

run c zk_app_utils.h YES
run cpp C++/zkAppUtilsClass.h NO
