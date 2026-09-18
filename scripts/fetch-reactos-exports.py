#!/usr/bin/env python3
"""Regenerate profiles/reactos-kernel32-exports.tsv from a ReactOS release ISO.

The xp list is a documentation scrape (scripts/fetch-exports.py). This one is
not: it reads the export tables of the DLLs the target actually ships, straight
out of the released image, so the profile it feeds can be checked against bytes
rather than against prose.

    pip install pycdlib pefile
    python3 scripts/fetch-reactos-exports.py ReactOS-0.4.16-i386.iso \
        > profiles/reactos-kernel32-exports.tsv

kernel32_vista.dll is reported as absent on purpose. It is one of ReactOS's
internal compatibility modules (kernel32_vista, ntdll_vista, advapi32_vista,
gdi32_vista): in the 0.4.16 image they are imported only by ReactOS's own DLLs
-- combase, msvcrt, ole32, oleaut32, msi, crypt32, atl and so on -- and never
by an application, and the names they carry are not in the app-facing
kernel32.dll. Pass --list-vista-importers to check that for yourself on a newer
image before trusting this.

With --all the whole system is dumped instead, one "dll<TAB>name" line per
export, which is what turns "does anything on this system export X" into a
grep. That dump is not committed: it is 35k lines, and only the kernel32 part
is what the audit reads.
"""

import argparse
import io
import sys

try:
    import pycdlib
    import pefile
except ImportError:  # pragma: no cover - a missing dependency is its own message
    sys.exit("needs pycdlib and pefile: pip install pycdlib pefile")

SYS32 = "/reactos/system32"


def system_files(iso, suffixes):
    for child in iso.list_children(iso_path=SYS32):
        if child.is_dot() or child.is_dotdot():
            continue
        name = child.file_identifier().decode()
        if name.lower().endswith(suffixes):
            yield name


def read(iso, name):
    buf = io.BytesIO()
    iso.get_file_from_iso_fp(buf, iso_path=SYS32 + "/" + name)
    return buf.getvalue()


def exports(data):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )
    out = set()
    for sym in getattr(pe, "DIRECTORY_ENTRY_EXPORT", type("", (), {"symbols": []})).symbols:
        if sym.name:
            out.add(sym.name.decode())
    pe.close()
    return out


def imports(data):
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    out = [entry.dll.decode().lower() for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
    pe.close()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iso", help="ReactOS-<version>-i386.iso")
    ap.add_argument("--version", default="0.4.16", help="version string for the header")
    ap.add_argument("--all", action="store_true", help="dump every system32 DLL as dll<TAB>name")
    ap.add_argument(
        "--list-vista-importers",
        action="store_true",
        help="list the modules that import a *_vista.dll, to confirm they are internal",
    )
    ap.add_argument(
        "--known",
        default="profiles/kernel32-exports.tsv",
        help="existing list whose names are carried over, so a function this target lacks "
        "is reported as absent instead of simply missing",
    )
    args = ap.parse_args()

    iso = pycdlib.PyCdlib()
    iso.open(args.iso)

    if args.list_vista_importers:
        for name in sorted(system_files(iso, (".dll", ".exe"))):
            try:
                for dll in imports(read(iso, name)):
                    if "_vista." in dll:
                        print("%s\t%s" % (name.lower(), dll))
            except Exception:
                continue
        return

    if args.all:
        for name in sorted(system_files(iso, (".dll",))):
            try:
                for sym in sorted(exports(read(iso, name))):
                    print("%s\t%s" % (name.lower(), sym))
            except Exception as err:
                print("# unreadable: %s (%s)" % (name, type(err).__name__), file=sys.stderr)
        return

    base = exports(read(iso, "kernel32.dll"))
    vista = exports(read(iso, "kernel32_vista.dll"))

    known = set()
    try:
        with open(args.known) as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                name = line.split("\t", 1)[0].strip()
                if name and name[0].isalpha() and name.isidentifier():
                    known.add(name)
    except OSError:
        pass

    print("# kernel32.dll exports and whether ReactOS %s (x86, reports NT 5.2) has them." % args.version)
    print("# Source: the export tables of \\reactos\\system32\\kernel32.dll and kernel32_vista.dll")
    print("# inside the released ReactOS-%s-i386 image, read with pefile. Not documentation:" % args.version)
    print("# these are the bytes the target actually ships. Format: name<TAB>reactos|no<TAB>where")
    print("# Names come from that image plus every name in kernel32-exports.tsv, so a function")
    print("# XP has and ReactOS lacks appears here as absent rather than simply missing.")
    print("# kernel32_vista.dll is marked absent on purpose: it is an internal ReactOS module,")
    print("# imported in that image only by ReactOS's own DLLs, never by an application.")
    print("# Regenerate with scripts/fetch-reactos-exports.py <ReactOS-%s-i386.iso>." % args.version)
    for name in sorted(base | vista | known):
        if name in base:
            print("%s\treactos\tkernel32.dll" % name)
        elif name in vista:
            print("%s\tno\tkernel32_vista.dll only" % name)
        else:
            print("%s\tno\tabsent" % name)


if __name__ == "__main__":
    main()
