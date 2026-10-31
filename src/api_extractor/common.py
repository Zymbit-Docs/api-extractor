"""Helpers shared by the Doxygen and Python extractors."""

import re

SCHEMA_VERSION = 1

SUPPORTED_RE = re.compile(r"Supported Devices:\s*([^)\n]+?)\s*(?:\)|\.?\s*$)", re.M)
DEVICE_TAG_RE = re.compile(r"\[((?:[A-Z][A-Za-z0-9 ]*,\s*)*[A-Z][A-Za-z0-9 ]*)\]")


class UnsupportedMarkup(Exception):
    """Raised for any documentation construct an extractor does not handle."""


def escape_html(text):
    """Make HTML in a comment render as literal text."""
    return text.replace("<", "&lt;").replace(">", "&gt;")


def escape_markdown(text):
    """Escape prose so Markdown and HTML in a comment render as literal text."""
    text = re.sub(r"([\\`*\[\]])", r"\\\1", text)
    text = escape_html(text)
    # Underscores only emphasize at word boundaries, so leave zk_app_utils alone.
    return re.sub(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])", r"\\_", text)


def code_span(text):
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def supported(*texts):
    """Devices named in a "Supported Devices: ..." phrase, in source order."""
    for text in texts:
        m = SUPPORTED_RE.search(text or "")
        if m:
            return [d.strip() for d in m.group(1).split(",") if d.strip()]
    return []


def anchor_for(name, used):
    """A readable anchor from a name; overloads get -2, -3, ..."""
    base = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
    used[base] = used.get(base, 0) + 1
    return base if used[base] == 1 else f"{base}-{used[base]}"
