#!/usr/bin/env python

#Only works with Python2 atm. Will have to make it work with Python3 before adding the code to cruloader_unpacker_downloader.py

import sys
import malduck

infile = sys.argv[1]

with open(infile,'rb') as f:
	payload = f.read()

png_marker = 'redaolurc'	
m = payload.find(png_marker)
png_marker_len = len('redaolurc')

trimmed_file = (payload[m+png_marker_len:])
dexor = malduck.xor(0x61, trimmed_file)

with open('trimmed.bin', 'wb') as o:
	o.write(dexor)
	
