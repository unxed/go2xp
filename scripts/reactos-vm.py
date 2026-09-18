#!/usr/bin/env python3
"""Drive a headless ReactOS VM: screenshots in, keystrokes out.

Why this is in the repo: XP cannot be put in CI, but ReactOS can. It is the
same NT 5.x-era API surface (0.4.16 reports NT 5.2), it boots in QEMU without
KVM, and everything this file does -- take a screenshot, press a key, type a
line, swap the CD that carries a new build in -- runs unattended over the QEMU
monitor socket. That is enough to answer "does the patched binary come up, and
does it still work after the next change" without anyone watching a screen.

    pip install pillow
    apt-get install qemu-system-x86 qemu-utils genisoimage

Install once (graphical installer; Alt+I installs, Alt+C creates the partition,
space ticks the confirmation box, Enter does the rest):

    qemu-img create -f qcow2 hdd.qcow2 6G
    python3 scripts/reactos-vm.py start --cd ReactOS-0.4.16-i386.iso --boot d
    python3 scripts/reactos-vm.py shot boot.png     # look, then send keys

Then, for each build:

    genisoimage -quiet -J -r -o payload.iso ./bundle-dir
    python3 scripts/reactos-vm.py start            # boots the installed system
    python3 scripts/reactos-vm.py cd payload.iso   # guest sees it as E:
    python3 scripts/reactos-vm.py key meta_l-r     # Run dialog
    python3 scripts/reactos-vm.py type cmd
    python3 scripts/reactos-vm.py key ret
    python3 scripts/reactos-vm.py run "copy e:\\\\probe.exe c:\\\\ & c: & probe.exe"
    python3 scripts/reactos-vm.py shot result.png

Nothing here is ReactOS-specific except the defaults: it drives any QEMU guest.

Two things worth knowing before a long session. Under TCG (no KVM) the guest
is roughly an order of magnitude slower than the host, so a boot takes minutes
and every wait below is generous on purpose. And the guest caches writes to its
own disks, so a build is handed over by swapping the CD, never by writing into
a disk image the running guest has mounted.
"""

import argparse
import os
import socket
import subprocess
import sys
import time

DIR = os.environ.get("REACTOS_VM_DIR", os.getcwd())
SOCK = os.path.join(DIR, "mon.sock")

SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal", "{": "bracket_left",
    "}": "bracket_right", ":": "semicolon", '"': "apostrophe", "<": "comma",
    ">": "dot", "?": "slash", "~": "grave_accent", "|": "backslash",
}
PLAIN = {
    " ": "spc", "-": "minus", "=": "equal", "[": "bracket_left", "]": "bracket_right",
    ";": "semicolon", "'": "apostrophe", ",": "comma", ".": "dot", "/": "slash",
    "\\": "backslash", "`": "grave_accent", "\n": "ret", "\t": "tab",
}


def monitor(commands, settle=0.25):
    """Send monitor commands over the unix socket and return what it echoed."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCK)
    sock.settimeout(2)
    out = b""
    time.sleep(0.2)
    try:
        out += sock.recv(65536)
    except socket.timeout:
        pass
    for command in commands:
        sock.sendall((command + "\n").encode())
        time.sleep(settle)
        try:
            out += sock.recv(65536)
        except socket.timeout:
            pass
    sock.close()
    return out.decode(errors="replace")


def key_name(ch):
    if ch.isdigit() or "a" <= ch <= "z":
        return ch
    if "A" <= ch <= "Z":
        return "shift-" + ch.lower()
    if ch in SHIFTED:
        return "shift-" + SHIFTED[ch]
    if ch in PLAIN:
        return PLAIN[ch]
    raise ValueError("no QEMU key name for %r" % ch)


def type_text(text, delay=0.06):
    # The monitor is a line protocol with a small buffer, so send in chunks.
    keys = ["sendkey " + key_name(c) for c in text]
    for i in range(0, len(keys), 20):
        monitor(keys[i:i + 20], settle=delay)


def start(args):
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    cmd = [
        "qemu-system-i386", "-M", "pc", "-cpu", "qemu32",
        "-m", str(args.memory), "-smp", "1",
        "-drive", "file=%s,if=ide,index=0,media=disk,format=qcow2" % args.disk,
        "-boot", args.boot, "-vga", "std", "-display", "none",
        "-monitor", "unix:%s,server,nowait" % SOCK,
        "-serial", "file:%s" % os.path.join(DIR, "serial.log"),
        "-net", "none",
    ]
    if args.cd:
        cmd[-2:-2] = ["-drive", "file=%s,if=ide,index=2,media=cdrom" % args.cd]
    log = open(os.path.join(DIR, "qemu.log"), "ab")
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                     start_new_session=True)
    for _ in range(40):
        if os.path.exists(SOCK):
            break
        time.sleep(0.5)
    print("started; the guest needs a few minutes to boot under TCG")


def shot(args):
    from PIL import Image  # imported here so the other commands need no pillow

    ppm = os.path.join(DIR, "screen.ppm")
    if os.path.exists(ppm):
        os.unlink(ppm)
    monitor(["screendump " + ppm])
    for _ in range(20):
        if os.path.exists(ppm) and os.path.getsize(ppm) > 1000:
            break
        time.sleep(0.3)
    Image.open(ppm).save(args.path)
    print(args.path)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("start", help="boot the VM, detached")
    p.add_argument("--disk", default=os.path.join(DIR, "hdd.qcow2"))
    p.add_argument("--cd", default=None)
    p.add_argument("--boot", default="c", help="c = hard disk, d = CD")
    p.add_argument("--memory", type=int, default=768)
    p.set_defaults(func=start)

    p = sub.add_parser("shot", help="save a screenshot")
    p.add_argument("path", nargs="?", default="screen.png")
    p.set_defaults(func=shot)

    p = sub.add_parser("key", help="send key names, e.g. ret esc f7 alt-i meta_l-r")
    p.add_argument("names", nargs="+")
    p.set_defaults(func=lambda a: monitor(["sendkey " + n for n in a.names]))

    p = sub.add_parser("type", help="type literal text (no Enter)")
    p.add_argument("text")
    p.set_defaults(func=lambda a: type_text(a.text))

    p = sub.add_parser("run", help="type a line, press Enter, wait")
    p.add_argument("line")
    p.add_argument("--wait", type=float, default=8)
    p.set_defaults(func=lambda a: (type_text(a.line), monitor(["sendkey ret"]),
                                   time.sleep(a.wait)))

    p = sub.add_parser("cd", help="swap the CD, which is how a new build gets in")
    p.add_argument("iso")
    p.add_argument("--device", default="ide1-cd0")
    p.set_defaults(func=lambda a: monitor(["change %s %s" % (a.device,
                                                            os.path.abspath(a.iso))]))

    p = sub.add_parser("monitor", help="raw monitor command")
    p.add_argument("command")
    p.set_defaults(func=lambda a: print(monitor([a.command])))

    p = sub.add_parser("stop", help="power the VM off")
    p.set_defaults(func=lambda a: monitor(["quit"]))

    args = ap.parse_args()
    if not os.path.exists(SOCK) and args.cmd != "start":
        sys.exit("no monitor socket at %s; start the VM first" % SOCK)
    args.func(args)


if __name__ == "__main__":
    main()
