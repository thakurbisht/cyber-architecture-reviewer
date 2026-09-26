import io
p = "app.py"
lines = io.open(p, encoding="utf-8").read().split("\n")
if lines[1605].strip() == "":
    del lines[1605]
    io.open(p, "w", encoding="utf-8").write("\n".join(lines))
    print("FIXED - blank line removed")
else:
    print("line 1606 is not blank:", repr(lines[1605]))
