#!/usr/bin/env python3
"""Print the byte offset of the squashfs payload inside an AppImage (type 2):
the end of the ELF runtime = e_shoff + e_shentsize * e_shnum. Used by
scripts/gates.sh (N2) so `unsquashfs -o <offset>` can unpack it without
executing the AppImage."""
import struct, sys

with open(sys.argv[1], "rb") as f:
    h = f.read(64)
if h[:4] != b"\x7fELF" or h[4] != 2:
    sys.exit("not a 64-bit ELF AppImage")
e_shoff, = struct.unpack_from("<Q", h, 0x28)
e_shentsize, e_shnum = struct.unpack_from("<HH", h, 0x3A)
off = e_shoff + e_shentsize * e_shnum
with open(sys.argv[1], "rb") as f:
    f.seek(off)
    if f.read(4) != b"hsqs":
        sys.exit("no squashfs magic at the computed offset")
print(off)
