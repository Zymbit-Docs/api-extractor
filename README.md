# api-extractor

Extracts API reference data from Zymbit library sources and writes it as JSON for the [Zymbit docs site](https://docs.zymbit.com), where Hugo templates render it.

- C and C++: reads Doxygen XML.
- Python: reads the source with [griffe](https://mkdocstrings.github.io/griffe/).

Libraries call this repo's reusable workflow on a release to open a pull request against [Zymbit-Docs/docs](https://github.com/Zymbit-Docs/docs). zkapputilslib is the first; others, such as zkpkcs11, can adopt it the same way.

Since November 2026 this is how docs.zymbit.com/api/ is built, replacing the Sphinx, Breathe, and [hugoify](https://github.com/Zymbit-Docs/actions-hugoify-api-docs) pipeline. How the docs repo renders and reviews the result is in its README, under "API reference".

## Usage

Python 3.10 or later. The one dependency is griffe, used only for Python pages.

```bash
python -m pip install -e '.[test]'
api-extractor doxygen path/to/xml --language c --header zk_app_utils.h \
    --repo zkapputilslib --version 1.2.0-11 --commit ec73411 -o c.json
api-extractor python zymkey --search-path path/to/zkapputilslib/python \
    --repo zkapputilslib --version 1.2.0-11 --commit ec73411 -o python.json
```

For `doxygen`, the first argument is Doxygen's XML output (the directory holding `index.xml`), and `--header` names the header whose page this is.

For `python`, griffe reads the package's source without importing it, so its native library does not need to be installed. The page covers what the package's `__all__` exports, and those classes' public methods and attributes. Docstrings are NumPy style; their reStructuredText inline markup (``` ``code`` ```, `` `name` ``, `` :class:`~a.B` ``) becomes Markdown.

## Output

One JSON file per language, with the same shape for all of them so one set of templates renders every page:

- `intro`, `brief`: the header's file comment or the module docstring, as Markdown.
- `groups`: one per Doxygen `@{ ... @}` group or section (C, C++), or Classes, Functions and Attributes (Python), each with `items`.
- Each item has `kind`, `name`, `anchor`, `signature`, `brief`, `details`, `params`, `returns` (a list: Python may document several), `throws`, `notes`, and `supported`. Enums add `values`; structs and classes add their own `groups`.
- `supported` lists the devices an item works on, from its supported-devices tag (below). A parameter's "only applicable for Supported Devices: ..." note is still prose and goes on that parameter's `supported`, not the item's.

## Supported devices

Tag each function or class in the source with the devices it works on. The tag becomes the item's `supported` list, which the site renders as badges, and is left out of the description text.

- **C and C++:** `@supported ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module`, on its own line after `@brief`. It is an alias in zkapputilslib's `docs/Doxyfile` for `@par Supported Devices:`.
- **Python:** a NumPy-style section, before `Parameters`:

    ```text
    Supported Devices
    -----------------
    ZYMKEY5, HSM60, HSM64, HSM6, Secure Compute Module
    ```

Device names must be in `DEVICES` in `src/api_extractor/common.py`, so a misspelled name stops the build instead of producing a wrong badge. Two tags on one item are also an error. An item without a tag falls back to a "Supported Devices: ..." phrase in its own text.

Descriptions are Markdown. Prose is escaped, so HTML or Markdown syntax written in a comment renders as literal text.

`anchor` is built from the name (`zkOpen`, `ZK_EC_KEY_TYPE`, `zkAppUtils-zkClass-lockData-2` for an overload, `Zymkey-set_battery_voltage_action` for a method), so it stays the same across releases and Doxygen versions.

## Publishing from a library repo

`.github/workflows/publish-docs.yml` is a reusable workflow. A library calls it on a release tag; it extracts the library's API reference with `scripts/extract-all.sh` and opens a pull request in Zymbit-Docs/docs that updates `data/api/<repo-name>/`. Nothing changes on docs.zymbit.com until someone reviews and merges that PR.

zkapputilslib's `.github/workflows/publish-docs.yml` is the working example. The call looks like this:

```yaml
jobs:
  docs:
    uses: Zymbit-Docs/api-extractor/.github/workflows/publish-docs.yml@<commit sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      repo-name: zkapputilslib
      doxyfile: docs/Doxyfile
      c-header: zk_app_utils.h
      cpp-header: C++/zkAppUtilsClass.h
      python-package: zymkey
      python-path: python
      intro: mainpage.md
      docs-intro-path: content/api/api_docs_intro.md
      extractor-ref: <the same commit sha>
      docs-app-client-id: ${{ vars.DOCS_APP_CLIENT_ID }}
    secrets:
      docs-app-private-key: ${{ secrets.DOCS_APP_PRIVATE_KEY }}
```

| Input | Meaning |
| --- | --- |
| `repo-name` | Directory under `data/api/` in the docs repo. Required. |
| `version` | Version shown on the pages. Default: `git describe --tags`, without a leading `v`. |
| `doxyfile` | The library's Doxyfile, used as-is except for what it reads and writes. Needed for C and C++. |
| `c-header`, `cpp-header` | The header for each page; leave one out to skip that page. |
| `python-package`, `python-path` | The Python package and the directory that contains it. |
| `intro`, `docs-intro-path` | A Markdown file copied into the docs repo as the API intro page. |
| `extractor-ref` | The api-extractor commit to run. Pass the commit the `uses:` line pins, so the workflow and the extractor always match. Required. |
| `docs-app-client-id`, secret `docs-app-private-key` | The GitHub App that may push a branch and open a PR in Zymbit-Docs/docs (below). |
| `dry-run` | Extract and upload the JSON as a run artifact, with no PR. Needs no App. |

**Pin by commit SHA,** not by a branch or tag, in both `uses:` and `extractor-ref`. A tag can be moved; a SHA cannot. To upgrade, change both to the new release's commit.

**Credentials.** The workflow gets a token from a GitHub App installed only on Zymbit-Docs/docs, with *Contents: write* and *Pull requests: write*. The token is limited to that repo, lasts at most an hour, and is revoked when the job ends. The calling repo stores the App's client ID as the variable `DOCS_APP_CLIENT_ID` and its private key as the secret `DOCS_APP_PRIVATE_KEY`. No personal token or deploy key is involved.

**What the PR contains.** The workflow rebuilds the branch `api-update/<repo-name>` from the docs repo's `main` on every run, so it only ever holds one commit: the new JSON files (and intro page). Other files in `data/api/<repo-name>/`, such as `legacy_anchors.json`, are left alone. If nothing changed, it opens no PR.

To run the extraction locally, with the same script:

```bash
REPO_NAME=zkapputilslib DOXYFILE=docs/Doxyfile C_HEADER=zk_app_utils.h \
CPP_HEADER=C++/zkAppUtilsClass.h PYTHON_PACKAGE=zymkey PYTHON_PATH=python INTRO=mainpage.md \
    scripts/extract-all.sh ../zkapputilslib /tmp/api-docs
```

## Strictness

A Doxygen element, section, or member kind, or a docstring section, that the extractor does not recognize stops it with an error rather than being skipped. Add support for it in `src/api_extractor/doxygen.py` or `python.py`, with a test, when one appears.

Source mistakes are kept visible rather than dropped:

- A parameter documented twice, or under a name the function does not declare, is kept and marked `"undeclared": true`.
- In Python, the type in the code's annotation wins. A docstring type that disagrees, including a leftover `TYPE` placeholder, is kept as `doc_type`.

## Tests

```bash
python -m pytest
```

The tests check that every word of every public comment and docstring in the fixtures reaches the JSON, that every public member becomes an item, and that Doxygen 1.9.1 (today's CI) and 1.9.8 give the same output.

## Test fixtures

Fixtures come only from public API files that ship in Zymbit packages, never from internal source.

- **C and C++:** Doxygen XML from the public headers. `scripts/make-fixtures.sh` regenerates it from a zkapputilslib checkout, with header source listings and local paths left out:

    ```bash
    scripts/make-fixtures.sh ../zkapputilslib tests/fixtures/zkapputilslib-<commit>/doxygen-<version>
    ```

- **Python:** a copy of the `zymkey` module's `__init__.py`, which ships as source in the `python3-zku` package under the MIT license, with that license alongside it.
