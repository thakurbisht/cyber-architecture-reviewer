import io
p = "app.py"
s = io.open(p, encoding="utf-8").read()
m = {
    "\u00c2\u00b7": "\u00b7",
    "\u00c3\u00b0\u0178\u203a\u00a1\u00c3\u00af\u00c2\u00b8\u008f": "\U0001F6E1\uFE0F",
    "\u00e2\u20ac\u201d": "\u2014",
    "\u00e2\u20ac\u2122": "\u2019",
}
n = 0
for a, b in m.items():
    c = s.count(a)
    if c:
        s = s.replace(a, b)
        n += c
        print("fixed", repr(a), "count", c)
io.open(p, "w", encoding="utf-8").write(s)
print("total:", n)
