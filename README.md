# api-extractor

Extracts API reference data from Zymbit library sources and writes it as JSON for the [Zymbit docs site](https://docs.zymbit.com), where Hugo templates render it.

- C and C++: reads Doxygen XML.
- Python: reads the source with [griffe](https://mkdocstrings.github.io/griffe/).

Libraries call this repo's reusable workflow on a release to open a pull request against [Zymbit-Docs/docs](https://github.com/Zymbit-Docs/docs). zkapputilslib is the first; others, such as zkpkcs11, can adopt it the same way.

This replaces the Sphinx, Breathe, and [hugoify](https://github.com/Zymbit-Docs/actions-hugoify-api-docs) pipeline. Work in progress; nothing here is used by the live site yet. Status: the C/C++ extractor is done; Python (griffe) and the reusable workflow are next.

## Usage

Python 3.9 or later; no runtime dependencies.

```bash
python -m pip install -e '.[test]'
api-extractor doxygen path/to/xml --language c --header zk_app_utils.h \
    --repo zkapputilslib --version 1.2.0-11 --commit c9b56b9 -o c.json
```

`<xml dir>` is Doxygen's XML output (the directory holding `index.xml`), and `--header` names the header whose page this is.

## Output

One JSON file per language, with the same shape for all of them so one set of templates renders every page:

- `intro`, `brief`: the header's file comment, as Markdown.
- `groups`: one per Doxygen `@{ ... @}` group or section, each with `items`.
- Each item has `kind`, `name`, `anchor`, `signature`, `brief`, `details`, `params`, `returns`, `throws`, `notes`, and `supported`. Enums add `values`; structs and classes add their own `groups`.

Descriptions are Markdown. Prose is escaped, so HTML or Markdown syntax written in a comment renders as literal text.

`anchor` is built from the name (`zkOpen`, `zkAppUtils-zkClass-lockData-2` for an overload), so it stays the same across releases and Doxygen versions.

## Strictness

A Doxygen element, section, or member kind the extractor does not recognize stops it with an error rather than being skipped. Add support for it in `src/api_extractor/doxygen.py`, with a test, when one appears.

A parameter documented twice, or documented under a name the function does not declare, is kept and marked `"undeclared": true`, so the text is not lost and the mistake stays visible.

## Tests

```bash
python -m pytest
```

The tests check that every word of every public comment in the fixtures reaches the JSON, that every public member becomes an item, and that Doxygen 1.9.1 (today's CI) and 1.9.8 give the same output.

## Test fixtures

Fixtures are generated only from the public API headers that ship in Zymbit packages, never from internal source. `scripts/make-fixtures.sh` regenerates them from a zkapputilslib checkout, with header source listings and local paths left out:

```bash
scripts/make-fixtures.sh ../zkapputilslib tests/fixtures/zkapputilslib-<commit>/doxygen-<version>
```
