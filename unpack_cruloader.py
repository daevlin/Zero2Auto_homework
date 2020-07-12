#!/usr/bin/env python3

#Todo Figure out how to ROL 4 with Python to then be able to XOR 0xC5 and find the Pastebin URL with regexp in Python

import malduck
import sys

infile = sys.argv[1]
outfile = infile + "_decrypted"

# RC4 key offset at 0xC
key_offset = 12

# RC4 key size
key_size = 15

# RC4 decrypt the first layer of CruLoader
p = malduck.pe(open(infile, "rb").read(), fast_load=False)
get_rsrc = p.resource('RT_RCDATA')
rc4_key = get_rsrc[key_offset:key_offset+key_size]
encrypted = get_rsrc[28:]
decrypted = malduck.rc4(rc4_key, encrypted)

if decrypted[0:2].decode('latin1') != "MZ":
	print("RC4 decryption failed")	
else:
	with open (outfile, 'wb') as o:
		o.write(decrypted)
