#!/usr/bin/env bash
# Extract every API reference page for one library into the docs repo layout.
#
# Usage: scripts/extract-all.sh <library checkout> <output dir>
#
# Settings come from the environment, so the publish workflow and a local run
# use the same script:
#
#   REPO_NAME       directory under data/api/ in the docs repo (required)
#   VERSION         library version shown on the pages; default: git describe
#   DOXYFILE        the library's Doxyfile, relative to the checkout
#   C_HEADER        C header to document (needs DOXYFILE)
#   CPP_HEADER      C++ header to document (needs DOXYFILE)
#   PYTHON_PACKAGE  Python package to document
#   PYTHON_PATH     directory that contains PYTHON_PACKAGE, relative to the checkout
#   INTRO           Markdown file copied as the API intro page
#
# Output: <output dir>/data/api/<REPO_NAME>/{c,cpp,python}.json, and
# <output dir>/intro.md when INTRO is set.
set -euo pipefail
SRC=$(realpath "$1")
OUT=$(realpath -m "$2")
: "${REPO_NAME:?REPO_NAME is required}"
VERSION=${VERSION:-$(git -C "$SRC" describe --tags --always)}
VERSION=${VERSION#v}
COMMIT=$(git -C "$SRC" rev-parse --short=7 HEAD)
DATA="$OUT/data/api/$REPO_NAME"
META=(--repo "$REPO_NAME" --version "$VERSION" --commit "$COMMIT")
mkdir -p "$DATA"

doxygen_page() {  # <language> <header> <OPTIMIZE_OUTPUT_FOR_C>
    local lang=$1 header=$2 for_c=$3 tmp
    : "${DOXYFILE:?DOXYFILE is required for C and C++ pages}"
    tmp=$(mktemp -d)
    # Settings after @INCLUDE override the library's own, so its Doxyfile is
    # used as-is apart from what to read and where to write.
    printf '%s\n' \
        "@INCLUDE = $SRC/$DOXYFILE" \
        "INPUT = $SRC/$header" \
        "OPTIMIZE_OUTPUT_FOR_C = $for_c" \
        "OUTPUT_DIRECTORY = $tmp/out" \
        "GENERATE_XML = YES" "GENERATE_HTML = NO" "GENERATE_LATEX = NO" \
        "XML_PROGRAMLISTING = NO" "QUIET = YES" > "$tmp/Doxyfile"
    (cd "$tmp" && doxygen Doxyfile)
    api-extractor doxygen "$tmp/out/xml" --language "$lang" --header "$(basename "$header")" \
        "${META[@]}" -o "$DATA/$lang.json"
    rm -rf "${tmp:?}"
}

[[ -n ${C_HEADER:-} ]] && doxygen_page c "$C_HEADER" YES
[[ -n ${CPP_HEADER:-} ]] && doxygen_page cpp "$CPP_HEADER" NO
if [[ -n ${PYTHON_PACKAGE:-} ]]; then
    api-extractor python "$PYTHON_PACKAGE" --search-path "$SRC/${PYTHON_PATH:-.}" \
        "${META[@]}" -o "$DATA/python.json"
fi
[[ -n ${INTRO:-} ]] && cp "$SRC/$INTRO" "$OUT/intro.md"

ls -l "$DATA"
