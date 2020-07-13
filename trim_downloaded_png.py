#!/usr/bin/env python3

import sys
import malduck

infile = sys.argv[1]

with open(infile,'rb') as f:
	payload = f.read()
#.decode('latin1')

png_marker = bytes('redaolurc', 'latin1')	
m = payload.find(png_marker)
png_marker_len = len('redaolurc')

trimmed_file = (payload[m+png_marker_len:])
dexor = malduck.xor(0x61, trimmed_file)

with open('trimmed.bin', 'wb') as o:
	o.write(dexor)
