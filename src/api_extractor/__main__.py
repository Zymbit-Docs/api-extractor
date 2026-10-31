"""Command line: api-extractor doxygen ... | api-extractor python ..."""

import argparse
import json
import sys

from . import common, doxygen


def main(argv=None):
    parser = argparse.ArgumentParser(prog="api-extractor")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doxygen", help="Doxygen XML (C, C++) to JSON")
    d.add_argument("xml_dir", help="Doxygen XML output directory (contains index.xml)")
    d.add_argument("--language", required=True, choices=["c", "cpp"])
    d.add_argument("--header", required=True, help="header file the page documents")
    py = sub.add_parser("python", help="Python package docstrings (via griffe) to JSON")
    py.add_argument("package", help="importable package name, e.g. zymkey")
    py.add_argument("--search-path", action="append", required=True,
                    help="directory containing the package (repeatable)")
    for p in (d, py):
        p.add_argument("--repo", default="", help="source repo name, recorded in the output")
        p.add_argument("--version", default="", help="library version, shown on the page")
        p.add_argument("--commit", default="", help="source commit, recorded in the output")
        p.add_argument("-o", "--output", help="output file (default: stdout)")
    args = parser.parse_args(argv)

    source = {"repo": args.repo, "version": args.version, "commit": args.commit}
    try:
        if args.command == "doxygen":
            data = doxygen.Extractor(args.xml_dir).extract(args.language, args.header, source)
        else:
            from . import python  # griffe is only needed for Python pages
            data = python.Extractor(args.package, args.search_path).extract(source)
    except common.UnsupportedMarkup as e:
        print(f"api-extractor: unsupported markup: {e}", file=sys.stderr)
        return 2
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
