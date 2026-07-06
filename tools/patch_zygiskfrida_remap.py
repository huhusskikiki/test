#!/usr/bin/env python3
# nop the gadget remap in lico-n ZygiskFrida (zygisk/arm64-v8a.so).
# the module mremaps the gadget to anon memory to hide it, but that segfaults
# gum-js-loop when a client connects, so the gadget is unusable. the remap fn
# (file offset 0x15cfc) returns its result via a struct the caller already filled
# with the original gadget address, so returning early leaves that address in
# place: gadget stays file-backed and the connect is stable.
#
#   python3 patch_zygiskfrida_remap.py arm64-v8a.so out.so
#   cp out.so over /data/adb/modules/zygiskfrida/zygisk/arm64-v8a.so ; reboot
#
# note: this un-hides the gadget, so pair it with make_stealth_gadget.py.
import sys
OFF = 0x15cfc
RET = bytes([0xc0, 0x03, 0x5f, 0xd6])  # ret
d = bytearray(open(sys.argv[1], 'rb').read())
print('@0x%x was %s' % (OFF, d[OFF:OFF+4].hex()))
d[OFF:OFF+4] = RET
open(sys.argv[2], 'wb').write(d)
print('patched ->', sys.argv[2])
