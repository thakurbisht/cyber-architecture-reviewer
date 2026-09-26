"""
Append a refine.css loader to the end of load_custom_css() in app.py.

Uses Python's own AST to find the exact end of the function, so it works
regardless of how long the inline <style> block is. Matches the style of
the existing loader: PROJECT_ROOT, try/except, explicit utf-8.

Backs up to app.py.pre-refine before writing. Idempotent.
Revert at any time with:
    Copy-Item app.py.pre-refine app.py -Force

Usage:
    python add_refine.py            # DRY RUN - shows exactly what changes
    python add_refine.py --apply    # back up, then write
"""
import ast
import io
import shutil
import sys

PATH = "app.py"
BACKUP = "app.py.pre-refine"
FUNC = "load_custom_css"
MARKER = "refine.css (added by patch"

SNIPPET = '''
    # --- refine.css (added by patch; delete this block to revert) ---
    refine_file = PROJECT_ROOT / "assets" / "refine.css"

    if refine_file.exists():
        try:
            refine_css = refine_file.read_text(
                encoding="utf-8",
                errors="ignore",
            )
            st.markdown(
                f"<style>{refine_css}</style>",
                unsafe_allow_html=True,
            )
        except Exception:
            pass
    # --- end refine.css ---
'''


def main():
    apply = "--apply" in sys.argv

    with io.open(PATH, encoding="utf-8", newline="") as f:
        original = f.read()

    if MARKER in original:
        print("Already patched - nothing to do.")
        print("Revert with:  Copy-Item %s %s -Force" % (BACKUP, PATH))
        return

    # Parse to locate the function precisely.
    try:
        tree = ast.parse(original)
    except SyntaxError as exc:
        print("app.py does not parse: %s" % exc)
        return

    target = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == FUNC:
            target = node
            break

    if target is None:
        print("Could not find def %s() in %s" % (FUNC, PATH))
        return

    start = target.lineno
    end = getattr(target, "end_lineno", None)
    if end is None:
        print("Python 3.8+ required (needs ast end_lineno).")
        return

    lines = original.splitlines(keepends=True)
    nl = "\r\n" if original.count("\r\n") > original.count("\n") / 2 else "\n"

    print("Found def %s() : lines %d-%d (%d lines)" % (
        FUNC, start, end, end - start + 1))
    print("")
    print("--- last 6 lines of the function ---")
    for i in range(max(start - 1, end - 6), end):
        print("%5d | %s" % (i + 1, lines[i].rstrip()))
    print("%5s + %s" % (">>>", "<<< new block appended here"))
    print("")
    print("--- block to append ---")
    for ln in SNIPPET.strip(nl).strip("\n").split("\n"):
        print("      | %s" % ln)

    if not apply:
        print("")
        print("DRY RUN - nothing written.")
        print("Re-run with --apply to back up and write.")
        return

    shutil.copyfile(PATH, BACKUP)
    block = SNIPPET.replace("\n", nl)
    lines.insert(end, block)

    with io.open(PATH, "w", encoding="utf-8", newline="") as f:
        f.write("".join(lines))

    # Prove the result still parses before declaring success.
    with io.open(PATH, encoding="utf-8", newline="") as f:
        try:
            ast.parse(f.read())
        except SyntaxError as exc:
            shutil.copyfile(BACKUP, PATH)
            print("Patch produced a syntax error - REVERTED. %s" % exc)
            return

    print("")
    print("Backed up to %s" % BACKUP)
    print("Patched %s - still parses OK." % PATH)
    print("Revert with:  Copy-Item %s %s -Force" % (BACKUP, PATH))


if __name__ == "__main__":
    main()
