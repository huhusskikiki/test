#!/usr/bin/env python3
# rename the frida thread names a stock frida-gadget.so creates, so the RASP
# can't find them in /proc/self/task/*/comm. same-length swaps only (don't move
# the ELF around), and leave the rpc strings alone so the client still talks.
#
#   python3 make_stealth_gadget.py frida-gadget.so frida-gadget-stealth.so
import sys
swaps = [
    (b'gum-js-loop',  b'mtk-js-loop'),
    (b'frida-gadget', b'androidmedia'),
    (b'gmain\x00',    b'hmain\x00'),
    (b'gdbus\x00',    b'hdbus\x00'),
    (b'pool-spawner', b'pool-svcwork'),
]
d = open(sys.argv[1], 'rb').read()
for a, b in swaps:
    assert len(a) == len(b)
    print('%dx %s -> %s' % (d.count(a), a.decode('latin1'), b.decode('latin1')))
    d = d.replace(a, b)
for s in (b'frida:rpc', b'frida/runtime'):
    assert d.count(s), 'broke %s' % s
open(sys.argv[2], 'wb').write(d)
print('wrote', sys.argv[2])
