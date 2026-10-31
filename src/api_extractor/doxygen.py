"""Turn Doxygen XML (C and C++) into the API reference JSON the docs site renders.

The extractor is strict on purpose: an element, section or member kind it does
not know raises ``UnsupportedMarkup`` instead of being dropped. The old pipeline
lost content silently, and a failed CI run is easier to notice than a missing
paragraph on the site.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA_VERSION = 1

# Section headings for Doxygen's own section kinds. "user-defined" sections are
# @{ ... @} groups and carry their own heading; private sections are skipped.
SECTION_TITLES = {
    "define": "Defines",
    "typedef": "Typedefs",
    "enum": "Enums",
    "func": "Functions",
    "var": "Variables",
    "public-type": "Public Types",
    "public-func": "Public Functions",
    "public-static-func": "Public Static Functions",
    "public-attrib": "Public Members",
    "public-static-attrib": "Public Static Members",
    "protected-type": "Protected Types",
    "protected-func": "Protected Functions",
    "protected-attrib": "Protected Members",
    "protected-static-attrib": "Protected Static Members",
}
PRIVATE_SECTIONS = {"private-type", "private-func", "private-static-func",
                    "private-attrib", "private-static-attrib"}

# Simple sections that become their own fields rather than prose.
NOTE_KINDS = {"note", "warning", "attention", "remark"}
META_KINDS = {"copyright", "version", "author", "date", "since"}

SUPPORTED_RE = re.compile(r"Supported Devices:\s*([^)\n]+?)\s*(?:\)|\.?\s*$)")


class UnsupportedMarkup(Exception):
    """Raised for any Doxygen construct the extractor does not handle."""


def _escape(text):
    """Escape prose so Markdown and HTML in a comment render as literal text."""
    text = re.sub(r"([\\`*\[\]])", r"\\\1", text)
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    # Underscores only emphasize at word boundaries, so leave zk_app_utils alone.
    return re.sub(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", r"\\_", text)


def _code_span(text):
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


class Converter:
    """Converts Doxygen description markup to Markdown."""

    def __init__(self, anchors):
        self.anchors = anchors  # Doxygen id -> page anchor, for <ref> links

    # Inline content -----------------------------------------------------

    def inline(self, elem):
        out = [_escape(elem.text or "")]
        for child in elem:
            out.append(self.inline_elem(child))
            out.append(_escape(child.tail or ""))
        return "".join(out)

    def inline_elem(self, e):
        tag = e.tag
        if tag == "computeroutput":
            return _code_span("".join(e.itertext()))
        if tag == "bold":
            return f"**{self.inline(e)}**"
        if tag == "emphasis":
            return f"*{self.inline(e)}*"
        if tag == "ref":
            text = "".join(e.itertext())
            anchor = self.anchors.get(e.get("refid"))
            return f"[{_escape(text)}](#{anchor})" if anchor else _escape(text)
        if tag == "ulink":
            return f"[{self.inline(e)}]({e.get('url')})"
        if tag == "linebreak":
            return "  \n"
        if tag == "sp":
            return " "
        raise UnsupportedMarkup(f"inline <{tag}>")

    # Block content ------------------------------------------------------

    BLOCK_TAGS = {"verbatim", "programlisting", "itemizedlist", "orderedlist",
                  "parameterlist", "simplesect"}

    def blocks(self, desc, fields):
        """Markdown blocks for a description element; params, returns,
        exceptions, notes and meta sections are moved into ``fields``."""
        out = []
        for para in desc:
            if para.tag != "para":
                raise UnsupportedMarkup(f"description child <{para.tag}>")
            out.extend(self.para(para, fields))
        return [b for b in out if b.strip()]

    def para(self, para, fields):
        out, run = [], [_escape(para.text or "")]

        def flush():
            text = "".join(run).strip()
            if text:
                out.append(text)
            run.clear()

        for child in para:
            if child.tag in self.BLOCK_TAGS:
                flush()
                block = self.block_elem(child, fields)
                if block:
                    out.append(block)
            else:
                run.append(self.inline_elem(child))
            run.append(_escape(child.tail or ""))
        flush()
        return out

    def block_elem(self, e, fields):
        tag = e.tag
        if tag == "verbatim":
            return "```\n" + (e.text or "").strip("\n") + "\n```"
        if tag == "programlisting":
            lines = ["".join(line.itertext()) for line in e.findall("codeline")]
            lang = (e.get("filename") or "").lstrip(".")
            return f"```{lang}\n" + "\n".join(lines) + "\n```"
        if tag in ("itemizedlist", "orderedlist"):
            return self.list_md(e, fields)
        if tag == "parameterlist":
            self.parameterlist(e, fields)
            return None
        if tag == "simplesect":
            self.simplesect(e, fields)
            return None
        raise UnsupportedMarkup(f"block <{tag}>")

    def list_md(self, e, fields):
        marker = "1." if e.tag == "orderedlist" else "-"
        items = []
        for li in e:
            if li.tag != "listitem":
                raise UnsupportedMarkup(f"list child <{li.tag}>")
            body = "\n\n".join(self.blocks(li, fields))
            indent = " " * (len(marker) + 1)
            items.append(f"{marker} " + body.replace("\n", "\n" + indent))
        return "\n".join(items)

    def parameterlist(self, e, fields):
        kind = e.get("kind")
        key = {"param": "params", "exception": "throws", "retval": "retvals",
               "templateparam": "template_params"}.get(kind)
        if key is None:
            raise UnsupportedMarkup(f"parameterlist kind={kind}")
        for item in e.findall("parameteritem"):
            names = item.findall("parameternamelist/parametername")
            text = "\n\n".join(self.blocks(item.find("parameterdescription"), fields))
            for name in names:
                fields.setdefault(key, []).append({
                    "name": "".join(name.itertext()).strip(),
                    "direction": name.get("direction"),
                    "description": text,
                })

    def simplesect(self, e, fields):
        kind = e.get("kind")
        text = "\n\n".join(self.blocks(e, fields))
        if kind == "return":
            fields["returns"] = text
        elif kind in NOTE_KINDS:
            fields.setdefault("notes", []).append({"kind": kind, "text": text})
        elif kind in META_KINDS:
            fields.setdefault("meta", {})[kind] = text
        elif kind in ("see", "pre", "post", "par"):
            fields.setdefault("see_also" if kind == "see" else kind, []).append(text)
        else:
            raise UnsupportedMarkup(f"simplesect kind={kind}")


def _text(elem):
    return " ".join("".join(elem.itertext()).split()) if elem is not None else ""


def _supported(*texts):
    for text in texts:
        m = SUPPORTED_RE.search(text or "")
        if m:
            return [d.strip() for d in m.group(1).split(",") if d.strip()]
    return []


class Extractor:
    def __init__(self, xml_dir):
        self.dir = Path(xml_dir)
        self.index = ET.parse(self.dir / "index.xml").getroot()
        self.anchors = {}
        self.compounds = {}
        for c in self.index.findall("compound"):
            path = self.dir / f"{c.get('refid')}.xml"
            if path.exists():
                self.compounds[c.get("refid")] = ET.parse(path).getroot().find("compounddef")
        self._assign_anchors()
        self.conv = Converter(self.anchors)

    def _assign_anchors(self):
        """Readable, stable anchors: the name, then name-2, name-3 for overloads."""
        used = {}
        for cdef in self.compounds.values():
            if cdef.get("kind") in ("struct", "class"):
                self._anchor(cdef.get("id"), cdef.findtext("compoundname"), used)
            for m in cdef.iter("memberdef"):
                owner = cdef.findtext("compoundname") if cdef.get("kind") in ("struct", "class") else ""
                self._anchor(m.get("id"), f"{owner}::{m.findtext('name')}" if owner else m.findtext("name"), used)

    def _anchor(self, refid, name, used):
        if refid in self.anchors:
            return
        base = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
        used[base] = used.get(base, 0) + 1
        self.anchors[refid] = base if used[base] == 1 else f"{base}-{used[base]}"

    def description(self, elem, fields):
        return "\n\n".join(self.conv.blocks(elem, fields)) if elem is not None else ""

    def member(self, m):
        kind = m.get("kind")
        if kind not in ("function", "define", "typedef", "enum", "variable"):
            raise UnsupportedMarkup(f"memberdef kind={kind}")
        fields = {}
        brief = self.description(m.find("briefdescription"), fields)
        details = self.description(m.find("detaileddescription"), fields)
        item = {
            "kind": kind,
            "name": m.findtext("name"),
            "id": m.get("id"),
            "anchor": self.anchors[m.get("id")],
            "protection": m.get("prot"),
            "signature": self.signature(m),
            "brief": brief,
            "details": details,
            "params": self.params(m, fields.pop("params", [])),
            "returns": None,
            "throws": [{"type": t["name"], "description": t["description"]}
                       for t in fields.pop("throws", [])],
            "notes": fields.pop("notes", []),
            "supported": _supported(_text(m.find("briefdescription")),
                                    _text(m.find("detaileddescription"))),
        }
        if kind == "function":
            rtype = _text(m.find("type"))
            item["returns"] = {"type": rtype, "description": fields.pop("returns", "")}
            for flag in ("static", "const", "virt"):
                if m.get(flag) not in (None, "no", "non-virtual"):
                    item[flag] = m.get(flag)
        if kind == "enum":
            item["values"] = [self.enumvalue(v) for v in m.findall("enumvalue")]
        if kind == "variable":
            item["type"] = _text(m.find("type"))
        item.update(fields)  # anything left (retvals, see_also, meta, ...)
        return item

    def enumvalue(self, v):
        fields = {}
        value = {
            "name": v.findtext("name"),
            "initializer": _text(v.find("initializer")).lstrip("= ").strip() or None,
            "brief": self.description(v.find("briefdescription"), fields),
            "details": self.description(v.find("detaileddescription"), fields),
        }
        value.update(fields)
        return value

    def params(self, m, documented):
        docs = {}
        for p in documented:
            docs.setdefault(p["name"], []).append(p)
        out = []
        for p in m.findall("param"):
            name = p.findtext("declname") or p.findtext("defname") or ""
            d = docs[name].pop(0) if docs.get(name) else {}
            out.append({
                "name": name,
                "type": _text(p.find("type")),
                "default": _text(p.find("defval")) or None,
                "direction": d.get("direction"),
                "description": d.get("description", ""),
            })
        # Documented names that match no declared parameter, or are documented
        # twice: keep them rather than lose the text, and let the page show them.
        for name, extra in docs.items():
            for d in extra:
                out.append({"name": name, "type": "", "default": None,
                            "direction": d.get("direction"), "description": d["description"],
                            "undeclared": True})
        return out

    def signature(self, m):
        kind = m.get("kind")
        if kind == "define":
            params = [p.findtext("defname") for p in m.findall("param")]
            args = f"({', '.join(params)})" if m.find("param") is not None else ""
            init = _text(m.find("initializer"))
            return f"#define {m.findtext('name')}{args}" + (f" {init}" if init else "")
        if kind == "enum":
            return f"enum {m.findtext('name')}"
        definition = _text(m.find("definition"))
        return definition + (m.findtext("argsstring") or "")

    def sections(self, cdef):
        groups = []
        for s in cdef.findall("sectiondef"):
            kind = s.get("kind")
            if kind in PRIVATE_SECTIONS:
                continue
            if kind == "user-defined":
                title = s.findtext("header") or "Other"
            elif kind in SECTION_TITLES:
                title = SECTION_TITLES[kind]
            else:
                raise UnsupportedMarkup(f"sectiondef kind={kind}")
            fields = {}
            desc = self.description(s.find("description"), fields)
            items = [self.member(m) for m in s.findall("memberdef")]
            if items:
                groups.append({"title": title, "description": desc, "items": items})
        return groups

    def compound(self, refid):
        cdef = self.compounds[refid]
        fields = {}
        item = {
            "kind": cdef.get("kind"),
            "name": cdef.findtext("compoundname"),
            "id": refid,
            "anchor": self.anchors[refid],
            "protection": cdef.get("prot"),
            "bases": [_text(b) for b in cdef.findall("basecompoundref")],
            "brief": self.description(cdef.find("briefdescription"), fields),
            "details": self.description(cdef.find("detaileddescription"), fields),
            "groups": self.sections(cdef),
        }
        item["notes"] = fields.pop("notes", [])
        item.update(fields)
        return item

    def extract(self, language, header, source=None):
        """JSON-ready dict for one language, rooted at its header file."""
        files = [c for c in self.compounds.values()
                 if c.get("kind") == "file" and c.findtext("compoundname") == header]
        if not files:
            raise ValueError(f"no file compound named {header} in {self.dir}")
        fdef = files[0]
        fields = {}
        intro = self.description(fdef.find("detaileddescription"), fields)
        brief = self.description(fdef.find("briefdescription"), fields)
        groups = self.sections(fdef)

        classes = [c.get("refid") for c in fdef.findall("innerclass")]
        for ns in fdef.findall("innernamespace"):
            ndef = self.compounds.get(ns.get("refid"))
            if ndef is None:
                continue  # e.g. std, mentioned but not documented
            groups.extend(self.sections(ndef))
            classes.extend(c.get("refid") for c in ndef.findall("innerclass")
                           if c.get("refid") not in classes)
        types = [self.compound(r) for r in classes
                 if r in self.compounds and self.compounds[r].get("prot") != "private"]
        if types:
            groups.append({"title": "Classes" if language == "cpp" else "Structs",
                           "description": "", "items": types})
        return {
            "schema": SCHEMA_VERSION,
            "language": language,
            "source": source or {},
            "header": header,
            "brief": brief,
            "intro": intro,
            "meta": fields.pop("meta", {}),
            "notes": fields.pop("notes", []),
            "groups": groups,
        }
