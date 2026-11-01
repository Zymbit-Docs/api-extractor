"""Helpers shared by the Doxygen and Python extractors."""

import re

SCHEMA_VERSION = 1

SUPPORTED_RE = re.compile(r"Supported Devices:\s*([^)\n]+?)\s*(?:\)|\.?\s*$)", re.M)
DEVICE_TAG_RE = re.compile(r"\[((?:[A-Z][A-Za-z0-9 ]*,\s*)*[A-Z][A-Za-z0-9 ]*)\]")

# Names allowed in an @supported tag (C/C++) or "Supported Devices" section
# (Python). A name outside this list is a typo until someone adds it here.
DEVICES = ("ZYMKEY5", "HSM60", "HSM64", "HSM6", "HSM4", "ZYMKEY4", "Secure Compute Module")
SUPPORTED_TITLE = "Supported Devices"


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


def devices(text, where):
    """The device list of an @supported tag, checked against DEVICES."""
    names = [d.strip() for d in text.rstrip(". \n").split(",")]
    unknown = [d for d in names if d not in DEVICES]
    if unknown or not names:
        raise UnsupportedMarkup(f"{SUPPORTED_TITLE} in {where}: unknown device(s) {unknown or text!r}")
    return names


def supported(*texts):
    """Devices named in a "Supported Devices: ..." phrase, in source order. Only
    parameter notes still use the phrase; items carry an @supported tag."""
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
