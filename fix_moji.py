"""
General mojibake repair for app.py.  Pure ASCII source - safe to paste
through any console, editor, or encoding.

Reverses UTF-8 bytes that were decoded as cp1252 ("mojibake"), e.g. the
shield emoji showing up as 7 garbage characters in your sidebar title.

Safety: a run of non-ASCII text is only rewritten where the characters
map back to single bytes AND those bytes form valid UTF-8. Correct text
fails one of those two tests and is left untouched. Where damage is
partial (a byte was destroyed at the time of corruption), as much as is
recoverable is recovered and the rest is left exactly as-is.

Usage:
    python fix_moji.py            # DRY RUN - shows what would change
    python fix_moji.py --apply    # actually writes the file
"""
import io
import re
import sys

PATH = "app.py"

RUN = re.compile(r"[^\x00-\x7f]+")


def to_byte(ch):
    """Map one character back to the single byte it was mis-decoded from.

    cp1252 first (it covers 0x80-0x9F, where the smart-quote / euro /
    caron characters live), then latin-1 for the plain 0xA0-0xFF range
    and the few slots cp1252 leaves undefined.
    Returns None if the character cannot have come from a single byte.
    """
    for enc in ("cp1252", "latin-1"):
        try:
            b = ch.encode(enc)
        except UnicodeEncodeError:
            continue
        if len(b) == 1:
            return b
    return None


def longest_valid(raw):
    """Decode the longest valid UTF-8 prefix of raw.

    Returns (decoded_text, bytes_consumed). Runs are a handful of bytes,
    so the quadratic scan costs nothing.
    """
    for n in range(len(raw), 0, -1):
        try:
            return raw[:n].decode("utf-8"), n
        except UnicodeDecodeError:
            continue
    return "", 0


def repair_run(run):
    """Rebuild one run of non-ASCII characters."""
    # Split into maximal mappable segments; unmappable chars are barriers
    # that stay literal (they were already destroyed, nothing to recover).
    segments, buf = [], []
    for ch in run:
        if to_byte(ch) is None:
            if buf:
                segments.append(("map", buf))
                buf = []
            segments.append(("lit", [ch]))
        else:
            buf.append(ch)
    if buf:
        segments.append(("map", buf))

    out = []
    for kind, chars in segments:
        if kind == "lit":
            out.append("".join(chars))
            continue
        raw = b"".join(to_byte(c) for c in chars)
        text, used = longest_valid(raw)
        out.append(text)
        out.append("".join(chars[used:]))  # trailing junk, unchanged
    return "".join(out)


def repair(text):
    out, last, changes = [], 0, []
    for m in RUN.finditer(text):
        run = m.group()
        new = repair_run(run)
        if new == run:
            continue
        out.append(text[last:m.start()])
        out.append(new)
        last = m.end()
        changes.append((text.count("\n", 0, m.start()) + 1, run, new))
    out.append(text[last:])
    return "".join(out), changes


def main():
    apply = "--apply" in sys.argv

    # newline="" preserves CRLF exactly - no line-ending surprises
    with io.open(PATH, encoding="utf-8", newline="") as f:
        original = f.read()

    fixed, changes = repair(original)

    if not changes:
        print("No mojibake found. Nothing to do.")
        return

    print("Found %d damaged run(s):" % len(changes))
    print("")
    for line, before, after in changes:
        print("  line %-6d %s" % (line, ascii(before)))
        print("         %-6s -> %s" % ("", ascii(after)))

    if not apply:
        print("")
        print("DRY RUN - nothing written.")
        print("Re-run with --apply to write the file.")
        return

    with io.open(PATH, "w", encoding="utf-8", newline="") as f:
        f.write(fixed)
    print("")
    print("Wrote %s (%d run(s) repaired)." % (PATH, len(changes)))


if __name__ == "__main__":
    main()
