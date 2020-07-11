#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#Check if Cruloader .png contains a 1 byte XOR:ed Windows binary 

import malduck
import sys

infile = sys.argv[1]

ruleset = malduck.Yara(name="XOR_PNG",
strings={
    "xor_png": malduck.YaraString("This program cannot", xor=True, ascii=True),

}, condition="$xor_png")


with open(infile, "rb") as f:
	p = f.read()
	
match = ruleset.match(data=p)

if match:
	 keys = list(match.keys())
	 print("Data matches Yara rule:" + " " + keys[0])

else:
	print("Yara rule does not match")
