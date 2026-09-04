#!/usr/bin/env python3
"""Regenerate profiles/kernel32-exports.tsv from Geoff Chappell's kernel32 export history.

That page lists every kernel32 export with the version range it exists in, which is the
closest thing to ground truth about XP available without an XP machine. Only kernel32 is
covered; names Go looks up in advapi32 & co. are XP-era with the exceptions listed in
docs/api-audit.md.
"""
import html, re, sys, urllib.request

URL = "https://www.geoffchappell.com/studies/windows/win32/kernel32/api/index.htm"
req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
page = urllib.request.urlopen(req, timeout=60).read().decode("utf-8", "replace")

exports = {}
for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page, flags=re.S):
    cells = [html.unescape(re.sub(r"<[^>]+>", "", c)).strip() for c in re.findall(r"<td[^>]*>(.*?)</td>", row, flags=re.S)]
    if len(cells) >= 2 and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cells[0]):
        exports[cells[0]] = cells[1]

def on_xp(v):
    m = re.match(r"^([0-9.]+)(?: and higher| to ([0-9.]+)| only)?", v)
    if not m:
        return None
    lo, hi = float(m.group(1)), m.group(2)
    if lo > 5.1 or ("only" in v and lo != 5.1) or (hi and float(hi) < 5.1):
        return False
    return True

with open("profiles/kernel32-exports.tsv", "w") as f:
    f.write("# kernel32.dll exports and whether Windows XP SP3 (5.1) has them.\n")
    f.write("# Source: Geoff Chappell, 'KERNEL32 Functions' (%s).\n" % URL)
    f.write("# Format: name<TAB>xp|no|?<TAB>version range. Regenerate with scripts/fetch-exports.py.\n")
    for n, v in sorted(exports.items()):
        x = on_xp(v)
        f.write("%s\t%s\t%s\n" % (n, "xp" if x else ("no" if x is False else "?"), v))
print("wrote %d exports, %d present on XP" % (len(exports), sum(1 for v in exports.values() if on_xp(v))), file=sys.stderr)
