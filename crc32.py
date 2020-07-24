#!/usr/bin/env python3

import zlib
import sys
import pefile

infile = sys.argv[1]

pe = pefile.PE(infile)

def get_exports():
	if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			 if exp.name is not None:
				 crc32 = str(hex(zlib.crc32(exp.name)))
				 export = str(exp.name, 'utf-8')
				 print(export + ' = ' + crc32)

def main():
	get_exports()
	
	return 0

if __name__ == '__main__':
	main()
	
