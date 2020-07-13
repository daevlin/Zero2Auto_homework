#!/usr/bin/env python

#Only works with Python2 atm. Will have to make it work with Python3 before adding it the logic to cruloader_unpacker_downloader.py

import sys
import malduck

infile = sys.argv[1]

with open(infile,'rb') as f:
	a = f.read()

c = 'redaolurc'	
m = a.find(c)
b = len('redaolurc')

trimmed_file = (a[m+b:])
dexor = malduck.xor(0x61, trimmed_file)

with open('trimmed.bin', 'wb') as o:
	o.write(dexor)
