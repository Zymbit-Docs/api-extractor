"""Command line: python -m api_extractor doxygen <xml dir> --language c --header zk_app_utils.h"""

import argparse
import json
import sys

from . import doxygen


def main(argv=None):
    parser = argparse.ArgumentParser(prog="api-extractor")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doxygen", help="Doxygen XML (C, C++) to JSON")
    d.add_argument("xml_dir", help="Doxygen XML output directory (contains index.xml)")
    d.add_argument("--language", required=True, choices=["c", "cpp"])
    d.add_argument("--header", required=True, help="header file the page documents")
    d.add_argument("--repo", default="", help="source repo name, recorded in the output")
    d.add_argument("--version", default="", help="library version, shown on the page")
    d.add_argument("--commit", default="", help="source commit, recorded in the output")
    d.add_argument("-o", "--output", help="output file (default: stdout)")
    args = parser.parse_args(argv)

    source = {"repo": args.repo, "version": args.version, "commit": args.commit}
    try:
        data = doxygen.Extractor(args.xml_dir).extract(args.language, args.header, source)
    except doxygen.UnsupportedMarkup as e:
        print(f"api-extractor: unsupported Doxygen markup: {e}", file=sys.stderr)
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
