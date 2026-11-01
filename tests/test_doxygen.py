import collections
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from api_extractor import doxygen

FIXTURES = Path(__file__).parent / "fixtures" / "zkapputilslib-ec73411"
VERSIONS = ["doxygen-1.9.1", "doxygen-1.9.8"]
PAGES = [("c", "zk_app_utils.h"), ("cpp", "zkAppUtilsClass.h")]
CASES = [(v, lang, header) for v in VERSIONS for lang, header in PAGES]
WORD = re.compile(r"[A-Za-z0-9]+")


def extract(version, lang, header):
    return doxygen.Extractor(FIXTURES / version / lang / "xml").extract(lang, header)


def all_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_strings(v)


def items(groups):
    for g in groups:
        for item in g["items"]:
            yield item
            yield from items(item.get("groups", []))


@pytest.mark.parametrize("version,lang,header", CASES)
def test_every_comment_word_reaches_the_json(version, lang, header):
    """The coverage check from the old pipeline, now a test: every word in every
    description Doxygen produced appears in the JSON at least as often."""
    data = extract(version, lang, header)
    have = collections.Counter(WORD.findall(" ".join(all_strings(data))))
    want = collections.Counter()
    for path in (FIXTURES / version / lang / "xml").glob("*.xml"):
        root = ET.parse(path).getroot()
        for cdef in root.iter("compounddef"):
            for section in cdef.iter("sectiondef"):
                if section.get("kind") in doxygen.PRIVATE_SECTIONS:
                    section.clear()
            # The @supported heading is structure; its devices are data.
            for sect in cdef.iter("simplesect"):
                title = sect.find("title")
                if title is not None and title.text == "Supported Devices:":
                    sect.remove(title)
            for tag in ("briefdescription", "detaileddescription"):
                for desc in cdef.iter(tag):
                    want.update(WORD.findall(" ".join(desc.itertext())))
    # Describing std:: or a private member is not our page's job.
    missing = {w: n - have[w] for w, n in want.items() if have[w] < n}
    assert not missing


@pytest.mark.parametrize("version,lang,header", CASES)
def test_every_public_member_is_an_item(version, lang, header):
    data = extract(version, lang, header)
    ids = {i["id"] for i in items(data["groups"])}
    xml_dir = FIXTURES / version / lang / "xml"
    expected = set()
    for path in xml_dir.glob("*.xml"):
        root = ET.parse(path).getroot()
        for cdef in root.iter("compounddef"):
            if cdef.findtext("compoundname") == "std":
                continue
            for m in cdef.iter("memberdef"):
                if m.get("prot") != "private":
                    expected.add(m.get("id"))
    assert expected <= ids


def test_versions_agree_apart_from_doxygen_ids():
    """Doxygen 1.9.1 (today's CI) and 1.9.8 give the same page."""
    def normalize(data):
        text = json.dumps(data, sort_keys=True)
        text = re.sub(r'"id": "[^"]*"', '"id": ""', text)
        return text.replace(" *", "*").replace("* ", "*")
    for lang, header in PAGES:
        assert normalize(extract(VERSIONS[0], lang, header)) == \
            normalize(extract(VERSIONS[1], lang, header))


def test_known_content():
    c = extract("doxygen-1.9.8", "c", "zk_app_utils.h")
    by_name = {i["name"]: i for i in items(c["groups"])}

    # Was missing from the site until zkapputilslib #6 grouped it.
    restart = by_name["zkEnableSelfRestart"]
    assert restart["signature"].startswith("int zkEnableSelfRestart(zkCTX ctx")
    assert [p["name"] for p in restart["params"]] == ["ctx", "enabled", "waitSec", "maxNumRestart"]
    assert restart["returns"][0]["description"].startswith("0 for success")

    # Usage code blocks, which hugoify dropped until this week.
    assert "```\nfind_package(zkAppUtils REQUIRED)" in c["intro"]
    assert "`libzk_app_utils-dev`" in c["intro"]

    # Supported devices parsed from the prose.
    assert by_name["zkGenWalletMasterSeedWithBIP39"]["supported"][:2] == ["ZYMKEY5", "HSM60"]

    # @note blocks, which hugoify never rendered.
    assert sum(len(i["notes"]) for i in items(c["groups"])) > 0


@pytest.mark.parametrize("lang,header,tagged", [("c", "zk_app_utils.h", 38),
                                                ("cpp", "zkAppUtilsClass.h", 36)])
def test_supported_tag_becomes_data(lang, header, tagged):
    data = extract("doxygen-1.9.1", lang, header)
    xml = FIXTURES / "doxygen-1.9.1" / lang / "xml"
    assert sum(p.read_text().count("<title>Supported Devices:</title>")
               for p in xml.glob("*.xml")) == tagged
    with_devices = [i for i in items(data["groups"]) if i["supported"]]
    assert len(with_devices) == tagged
    for i in with_devices:
        assert i["supported"] in (["ZYMKEY5", "HSM60", "HSM64", "HSM6", "Secure Compute Module"],
                                  ["Secure Compute Module"])
        assert "Supported Devices" not in i["brief"] + i["details"]


def test_supported_tag_content():
    c = extract("doxygen-1.9.1", "c", "zk_app_utils.h")
    by_name = {i["name"]: i for i in items(c["groups"])}
    assert by_name["zkDoRawECDH"]["brief"] == "Perform a raw ECDH operation."
    assert by_name["zkSetSupervisedBootPolicy"]["supported"] == ["Secure Compute Module"]
    assert by_name["zkGenWalletChildKey"]["brief"] == "Generate child key from a parent key in a blockchain wallet."
    # Parameter notes are still prose, and still parsed.
    param = next(p for p in by_name["zkExportPubKey2File"]["params"] if p["name"] == "slot_is_foreign")
    assert param["supported"][0] == "ZYMKEY5"


SUPPORTED = '<simplesect kind="par"><title>Supported Devices:</title><para>{}</para></simplesect>'


@pytest.mark.parametrize("tags", [
    [SUPPORTED.format("HSM60, HSM7")],                        # typo or unknown device
    [SUPPORTED.format("HSM6"), SUPPORTED.format("HSM60")],    # two tags
])
def test_bad_supported_tag_fails_loudly(tags):
    conv = doxygen.Converter({})
    desc = ET.fromstring(f"<detaileddescription><para>{''.join(tags)}</para></detaileddescription>")
    with pytest.raises(doxygen.UnsupportedMarkup):
        conv.blocks(desc, {})


def test_cpp_gaps_are_filled():
    cpp = extract("doxygen-1.9.8", "cpp", "zkAppUtilsClass.h")
    names = {i["name"] for i in items(cpp["groups"])}
    # Exception classes hugoify never rendered.
    assert {"zkAppUtils::commonException", "zkAppUtils::timeoutException"} <= names
    rsb = next(i for i in items(cpp["groups"]) if i["name"] == "zkAppUtils::recoveryStrategyBaseType")
    protected = [m for g in rsb["groups"] for m in g["items"] if m["protection"] == "protected"]
    assert protected


def test_anchors_are_unique_and_readable():
    cpp = extract("doxygen-1.9.8", "cpp", "zkAppUtilsClass.h")
    anchors = [i["anchor"] for i in items(cpp["groups"])]
    assert len(anchors) == len(set(anchors))
    assert all(re.fullmatch(r"[A-Za-z0-9-]+", a) for a in anchors)


def test_unknown_markup_fails_loudly():
    conv = doxygen.Converter({})
    desc = ET.fromstring("<detaileddescription><para>Hi <blink>there</blink></para></detaileddescription>")
    with pytest.raises(doxygen.UnsupportedMarkup):
        conv.blocks(desc, {})


@pytest.mark.parametrize("raw,expected", [
    ("a <script>x</script>", "a &lt;script&gt;x&lt;/script&gt;"),
    ("[HSM6](http://x)", "\\[HSM6\\](http://x)"),
    ("2 * 3", "2 \\* 3"),
    ("zk_app_utils", "zk_app_utils"),
    ("_lead", "\\_lead"),
])
def test_prose_is_escaped(raw, expected):
    assert doxygen._escape(raw) == expected
