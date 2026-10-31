# api-extractor

Extracts API reference data from Zymbit library sources and writes it as JSON for the [Zymbit docs site](https://docs.zymbit.com), where Hugo templates render it.

- C and C++: reads Doxygen XML.
- Python: reads the source with [griffe](https://mkdocstrings.github.io/griffe/).

Libraries call this repo's reusable workflow on a release to open a pull request against [Zymbit-Docs/docs](https://github.com/Zymbit-Docs/docs). zkapputilslib is the first; others, such as zkpkcs11, can adopt it the same way.

This replaces the Sphinx, Breathe, and [hugoify](https://github.com/Zymbit-Docs/actions-hugoify-api-docs) pipeline. Work in progress; nothing here is used by the live site yet.

## Test fixtures

Fixtures are generated only from the public API headers that ship in Zymbit packages, never from internal source.
