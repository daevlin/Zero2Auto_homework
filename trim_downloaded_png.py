#!/usr/bin/env python

import sys
import malduck

infile = sys.argv[1]

with open(infile,'rb') as f:
	a = f.read()
#.decode('latin1')

c = 'redaolurc'	
m = a.find(c)
b = len('redaolurc')

trimmed_file = (a[m+b:])
dexor = malduck.xor(0x61, trimmed_file)

with open('trimmed.bin', 'wb') as o:
	o.write(dexor)
