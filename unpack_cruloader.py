#!/usr/bin/env python3

import malduck
import sys

infile = sys.argv[1]
outfile = infile + "_decrypted"

#RC4 decrypt the first layer of CruLoader

p = malduck.pe(open(infile, "rb").read(), fast_load=False)
get_rsrc = p.resource(101)
rc4_key = get_rsrc[12:27]
encrypted = get_rsrc[28:]
decrypted = malduck.rc4(rc4_key, encrypted)

with open (outfile, 'wb') as o:
	o.write(decrypted)