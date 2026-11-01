import ast
import collections
import re
from pathlib import Path

import pytest

from api_extractor import python as px
from api_extractor.common import UnsupportedMarkup

FIXTURE = Path(__file__).parent / "fixtures" / "zkapputilslib-ec73411" / "python"
WORD = re.compile(r"[A-Za-z0-9]+")


@pytest.fixture(scope="module")
def page():
    return px.Extractor("zymkey", [FIXTURE]).extract()


def items(groups):
    for g in groups:
        for item in g["items"]:
            yield item
            yield from items(item.get("groups", []))


def all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_strings(v)


def public_docstrings():
    """Docstrings of the module and of every public class, method and
    documented attribute, read straight from the source with ast."""
    tree = ast.parse((FIXTURE / "zymkey" / "__init__.py").read_text())
    exported = next(ast.literal_eval(n.value) for n in tree.body
                    if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "__all__")
    docs = [ast.get_docstring(tree, clean=True)]

    def walk(node):
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.ClassDef)):
                if child.name.startswith("_") and child.name != "__init__":
                    continue
                docs.append(ast.get_docstring(child, clean=True))
                if isinstance(child, ast.ClassDef):
                    walk(child)

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name in exported:
            docs.append(ast.get_docstring(node, clean=True))
            walk(node)
    return [d for d in docs if d]


def test_every_docstring_word_reaches_the_json(page):
    have = collections.Counter(WORD.findall(" ".join(all_strings(page))))
    want = collections.Counter()
    for doc in public_docstrings():
        # NumPy section headings and their underlines are structure, not text.
        doc = re.sub(r"^(\w[\w ]*)\n-{3,}$", "", doc, flags=re.M)
        want.update(WORD.findall(doc))
    missing = {w: n - have[w] for w, n in want.items() if have[w] < n}
    assert not missing


def test_matches_the_live_page(page):
    """Everything today's Python page documents is here (except __del__),
    plus the exported `client`."""
    names = {i["name"] for i in items(page["groups"])}
    zymkey = next(i for i in items(page["groups"]) if i["name"] == "Zymkey")
    methods = {i["name"] for g in zymkey["groups"] if g["title"] == "Methods" for i in g["items"]}
    assert len(methods) == 64
    assert {"__init__", "sign", "lock", "unlock", "get_supervised_boot_file_manifest"} <= methods
    assert "__del__" not in names
    assert {"EPHEMERAL_KEY_SLOT", "ZymkeyAccelAxisData", "RecoveryStrategy",
            "RecoveryStrategyBIP39", "RecoveryStrategySLIP39", "client"} <= names
    # Private helpers and the ctypes bindings stay out.
    assert not [n for n in names if n.startswith("_") and n != "__init__"]


def test_known_content(page):
    assert page["brief"] == "Python interface module to Zymkey Application Utilities Library."
    assert "`python3-zku`" in page["intro"]
    assert "1. Signing of payloads using ECDSA" in page["intro"]

    sign = next(i for i in items(page["groups"]) if i["name"] == "sign")
    assert sign["signature"].startswith("def sign(src: t.Union[str, bytes, bytearray], slot: int = 0")
    assert [r["type"] for r in sign["returns"]] == ["bytearray", "int"]
    assert sign["notes"] == [{"kind": "todo", "text": "Allow for overloading of source parameter "
                                                      "in similar fashion to lock/unlock."}]
    slot = next(p for p in sign["params"] if p["name"] == "slot")
    assert slot["default"] == "0"
    assert slot["description"].startswith("The key slot used for signing. \\[ZYMKEY5, HSM60, HSM64, HSM6\\]")

    sign_digest = next(i for i in items(page["groups"]) if i["name"] == "sign_digest")
    assert sign_digest["throws"][0]["type"] == "AssertionError"
    assert "`ret`" in sign_digest["throws"][0]["description"]


def test_anchors_are_unique_and_readable(page):
    anchors = [i["anchor"] for i in items(page["groups"])]
    assert len(anchors) == len(set(anchors))
    assert "Zymkey-sign" in anchors


@pytest.mark.parametrize("rst,md", [
    ("needs ``python3-zku`` installed", "needs `python3-zku` installed"),
    ("If `ret` is bad", "If `ret` is bad"),
    ("see :class:`~zymkey.Zymkey`", "see `Zymkey`"),
    ("see :meth:`zymkey.Zymkey.sign`", "see `zymkey.Zymkey.sign`"),
    ("[HSM6] slot", "\\[HSM6\\] slot"),
    ("a <b>bold</b> claim", "a &lt;b&gt;bold&lt;/b&gt; claim"),
    ("* `\"none\"`: just the secret", "* `\"none\"`: just the secret"),
])
def test_rst_to_markdown(rst, md):
    assert px.rst_to_md(rst) == md


def test_unknown_docstring_section_fails_loudly(tmp_path):
    pkg = tmp_path / "demo"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        '__all__ = ["f"]\n'
        'def f(x):\n'
        '    """Do it.\n\n    Yields\n    ------\n    int\n        A number.\n    """\n')
    with pytest.raises(UnsupportedMarkup):
        px.Extractor("demo", [tmp_path]).extract()


def test_supported_section_becomes_data(page):
    src = (FIXTURE / "zymkey" / "__init__.py").read_text()
    tagged = src.count("Supported Devices\n        -----------------")
    assert tagged == 33
    with_devices = [i for i in items(page["groups"]) if i["supported"]]
    assert len(with_devices) == tagged
    for i in with_devices:
        assert "Supported Devices" not in i["brief"] + i["details"]
        assert not [n for n in i["notes"] if n["kind"] == "supported-devices"]
    by_name = {i["name"]: i for i in items(page["groups"])}
    assert by_name["ecdh"]["supported"] == ["ZYMKEY5", "HSM60", "HSM64", "HSM6", "Secure Compute Module"]
    assert by_name["set_supervised_boot_policy"]["supported"] == ["Secure Compute Module"]
    # Parameter notes are still prose, and still parsed.
    foreign = next(p for p in by_name["get_slot_alloc_list"]["params"] if p["name"] == "foreign")
    assert foreign["supported"][0] == "ZYMKEY5"


@pytest.mark.parametrize("section", [
    "Supported Devices\n    -----------------\n    HSM60, HSM7\n",
    "Supported Devices\n    -----------------\n    HSM6\n\n    Supported Devices\n    -----------------\n    HSM60\n",
])
def test_bad_supported_section_fails_loudly(tmp_path, section):
    pkg = tmp_path / "demo"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        '__all__ = ["f"]\n'
        f'def f(x):\n    """Do it.\n\n    {section}    """\n')
    with pytest.raises(UnsupportedMarkup):
        px.Extractor("demo", [tmp_path]).extract()


def test_docstring_type_beats_a_bare_any(page):
    by_name = {i["name"]: i for i in items(page["groups"])}
    digest = next(p for p in by_name["sign"]["params"] if p["name"] == "digest")
    assert (digest["type"], digest["doc_type"]) == ("_hashlib.HASH", "t.Any")
    # A "TYPE" placeholder never beats the code, even an Any.
    digest = next(p for p in by_name["verify_digest"]["params"] if p["name"] == "digest")
    assert (digest["type"], digest["doc_type"]) == ("t.Any", "TYPE")
