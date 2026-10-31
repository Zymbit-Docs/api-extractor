"""Turn a Python package's docstrings into the API reference JSON, using griffe.

griffe reads the source without importing it, so the package's native library
(``libzk_app_utils``) does not need to be installed. Docstrings are NumPy style;
their reStructuredText inline markup becomes Markdown. As with Doxygen, a
docstring section the extractor does not know is an error, not a silent drop.
"""

import re

import griffe

from .common import (SCHEMA_VERSION, SUPPORTED_TITLE, UnsupportedMarkup, anchor_for,
                     code_span, devices, escape_html, supported)

INLINE_RE = re.compile(
    r"``(?P<literal>.+?)``"                      # ``literal``
    r"|:[\w:.-]+:`~?(?P<role>[^`]+)`"            # :class:`~zymkey.Zymkey`
    r"|`(?P<interpreted>[^`]+)`(?!_)",           # `default role`
    re.S,
)


def rst_to_md(text):
    """Docstring prose (reStructuredText) to escaped Markdown."""
    out, pos = [], 0
    for m in INLINE_RE.finditer(text):
        out.append(_escape_rst_prose(text[pos:m.start()]))
        if m.group("role"):
            target = m.group("role")
            # :role:`~a.b.c` displays as c; :role:`title <target>` as title.
            target = re.sub(r"\s*<[^>]*>$", "", target)
            out.append(code_span(target.rsplit(".", 1)[-1] if m.group(0).count("~") else target))
        else:
            out.append(code_span(m.group("literal") or m.group("interpreted")))
        pos = m.end()
    out.append(_escape_rst_prose(text[pos:]))
    return "".join(out).strip()


def _escape_rst_prose(text):
    # *emphasis*, **strong** and "* " bullets mean the same in reST and
    # Markdown, so asterisks pass through; brackets and HTML do not.
    return escape_html(re.sub(r"([\\\[\]])", r"\\\1", text))


def _split_brief(text):
    parts = re.split(r"\n\s*\n", text.strip(), maxsplit=1)
    return parts[0].strip(), (parts[1].strip() if len(parts) > 1 else "")


def _str(expr):
    return str(expr) if expr is not None else ""


class Extractor:
    def __init__(self, package, search_paths):
        self.module = griffe.load(package, search_paths=list(search_paths),
                                  docstring_parser="numpy", allow_inspection=False,
                                  resolve_aliases=False)
        self.used_anchors = {}

    # Docstrings -----------------------------------------------------------

    def docstring(self, obj):
        """Fields from an object's docstring: brief, details, params, returns,
        throws, notes, examples."""
        fields = {"brief": "", "details": "", "doc_params": [], "returns": [],
                  "throws": [], "notes": [], "examples": [], "supported": None}
        if not obj.docstring:
            return fields
        texts = []
        for section in obj.docstring.parse("numpy"):
            kind = section.kind.value
            if kind == "text":
                texts.append(section.value)
            elif kind in ("parameters", "other parameters"):
                for p in section.value:
                    fields["doc_params"].append({
                        "name": p.name, "type": _str(p.annotation),
                        "default": p.default, "description": rst_to_md(p.description)})
            elif kind == "returns":
                for r in section.value:
                    fields["returns"].append({
                        "name": r.name or None, "type": _str(r.annotation),
                        "description": rst_to_md(r.description)})
            elif kind == "raises":
                for r in section.value:
                    fields["throws"].append({"type": _str(r.annotation),
                                             "description": rst_to_md(r.description)})
            elif kind == "admonition" and section.title == SUPPORTED_TITLE:
                # Matches the C/C++ @supported tag; napoleon_custom_sections in
                # zkapputilslib's Sphinx config renders it on the old pages.
                if fields["supported"] is not None:
                    raise UnsupportedMarkup(f"two {SUPPORTED_TITLE} sections in {obj.path}")
                fields["supported"] = devices(" ".join(section.value.description.split()), obj.path)
            elif kind == "admonition":
                fields["notes"].append({"kind": (section.title or section.value.kind).lower(),
                                        "text": rst_to_md(section.value.description)})
            elif kind == "examples":
                for sub_kind, body in section.value:
                    if sub_kind.value == "examples":
                        fields["examples"].append(f"```python\n{body}\n```")
                    else:
                        fields["examples"].append(rst_to_md(body))
            elif kind == "deprecated":
                fields["notes"].append({"kind": "deprecated",
                                        "text": rst_to_md(section.value.description)})
            else:
                raise UnsupportedMarkup(f"docstring section {kind!r} in {obj.path}")
        brief, rest = _split_brief(texts[0]) if texts else ("", "")
        fields["brief"] = rst_to_md(brief)
        fields["details"] = "\n\n".join(rst_to_md(t) for t in [rest, *texts[1:]] if t.strip())
        return fields

    # Objects ----------------------------------------------------------------

    def params(self, func, documented):
        docs = {}
        for p in documented:
            docs.setdefault(p["name"], []).append(p)
        out = []
        for p in func.parameters:
            if p.name in ("self", "cls"):
                continue
            d = docs[p.name].pop(0) if docs.get(p.name) else {}
            param = {
                "name": p.name,
                "type": _str(p.annotation) or d.get("type", ""),
                "default": _str(p.default) or None,
                "direction": None,
                "description": d.get("description", ""),
                "supported": supported(d.get("description", "")),
            }
            # The code's annotation wins; keep a docstring type that disagrees
            # (or is a leftover "TYPE" placeholder) so it can be fixed upstream.
            if d.get("type") and d["type"] != param["type"]:
                param["doc_type"] = d["type"]
            out.append(param)
        for name, extra in docs.items():
            for d in extra:
                out.append({"name": name, "type": d["type"], "default": None,
                            "direction": None, "description": d["description"],
                            "supported": supported(d["description"]), "undeclared": True})
        return out

    def signature(self, func, keyword="def", name=None):
        parts, star_done = [], False
        for p in func.parameters:
            if p.name in ("self", "cls"):
                continue
            kind = p.kind.value if p.kind else ""
            text = p.name
            if kind == "variadic positional":
                text, star_done = "*" + p.name, True
            elif kind == "variadic keyword":
                text = "**" + p.name
            elif kind == "keyword-only" and not star_done:
                parts.append("*")
                star_done = True
            if p.annotation is not None:
                text += f": {p.annotation}"
            if p.default is not None:
                text += f" = {p.default}" if p.annotation is not None else f"={p.default}"
            parts.append(text)
        ret = f" -> {func.returns}" if keyword == "def" and func.returns is not None else ""
        return f"{keyword} {name or func.name}({', '.join(parts)}){ret}"

    def item(self, obj, kind, signature, params=None, extra=None):
        d = self.docstring(obj)
        item = {
            "kind": kind,
            "name": obj.name,
            "id": obj.path,
            "anchor": anchor_for(obj.path.split(".", 1)[-1], self.used_anchors),
            "protection": "public",
            "signature": signature,
            "brief": d["brief"],
            "details": d["details"],
            "params": params if params is not None else [],
            "returns": [],
            "throws": d["throws"],
            "notes": d["notes"],
            "supported": d["supported"] or supported(d["brief"], d["details"]),
        }
        if d["examples"]:
            item["examples"] = d["examples"]
        if extra:
            item.update(extra)
        return item, d

    def function(self, func, kind="function"):
        d = self.docstring(func)
        params = self.params(func, d["doc_params"])
        item, d = self.item(func, kind, self.signature(func), params)
        returns = d["returns"]
        code_type = _str(func.returns)
        if not returns and code_type and code_type != "None":
            returns = [{"name": None, "type": code_type, "description": ""}]
        elif len(returns) == 1 and code_type and returns[0]["type"] != code_type:
            # As for parameters, the annotation wins and the docstring's type is kept.
            returns[0]["doc_type"], returns[0]["type"] = returns[0]["type"], code_type
        item["returns"] = returns
        return item

    def attribute(self, attr):
        annotation = _str(attr.annotation)
        value = _str(attr.value)
        sig = attr.name + (f": {annotation}" if annotation else "") + (f" = {value}" if value else "")
        item, _ = self.item(attr, "attribute", sig, extra={"type": annotation, "value": value or None})
        return item

    def cls(self, klass):
        init = klass.members.get("__init__")
        if init is not None and init.is_function:
            sig = self.signature(init, keyword="class", name=klass.name)
        else:
            sig = f"class {klass.name}"
        item, _ = self.item(klass, "class", sig,
                            extra={"bases": [_str(b) for b in klass.bases]})
        methods, attributes, classes = [], [], []
        for name, member in klass.members.items():
            if member.is_alias or not self.is_public(name, member):
                continue
            if member.is_function:
                methods.append(self.function(member, "method"))
            elif member.is_attribute:
                # Instance attributes set in __init__ are implementation unless documented.
                if "class-attribute" not in member.labels and not member.docstring:
                    continue
                attributes.append(self.attribute(member))
            elif member.is_class:
                classes.append(self.cls(member))
        item["groups"] = [g for g in (
            {"title": "Attributes", "description": "", "items": attributes},
            {"title": "Methods", "description": "", "items": methods},
            {"title": "Classes", "description": "", "items": classes},
        ) if g["items"]]
        return item

    @staticmethod
    def is_public(name, member):
        if name == "__init__":
            return True
        return not name.startswith("_")

    # Page -------------------------------------------------------------------

    def exported(self):
        exports = self.module.exports
        if exports:
            return [str(e) for e in exports]
        return [n for n, m in self.module.members.items()
                if not n.startswith("_") and not m.is_alias and not m.is_module]

    def extract(self, source=None):
        classes, functions, attributes = [], [], []
        for name in self.exported():
            member = self.module.members.get(name)
            if member is None:
                raise ValueError(f"{self.module.path}.__all__ names {name}, which is not defined")
            if member.is_alias:
                raise UnsupportedMarkup(f"exported alias {name}: document it where it is defined")
            if member.is_class:
                classes.append(self.cls(member))
            elif member.is_function:
                functions.append(self.function(member))
            elif member.is_attribute:
                attributes.append(self.attribute(member))
            else:
                raise UnsupportedMarkup(f"exported {member.kind.value} {name}")
        d = self.docstring(self.module)
        return {
            "schema": SCHEMA_VERSION,
            "language": "python",
            "source": source or {},
            "module": self.module.path,
            "brief": d["brief"],
            "intro": d["details"],
            "meta": {},
            "notes": d["notes"],
            "groups": [g for g in (
                {"title": "Classes", "description": "", "items": classes},
                {"title": "Functions", "description": "", "items": functions},
                {"title": "Attributes", "description": "", "items": attributes},
            ) if g["items"]],
        }
