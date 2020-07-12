#!/usr/bin/env python3
# WHat? Who needs error handling?
# Script does not work atm, until I figure out how to join those ints in the rol array and then feed them to malduck.xor as bytes

import malduck
import sys
import re
import requests

infile = sys.argv[1]
# URL regexp from https://www.w3resource.com/python-exercises/re/python-re-exercise-42.php
url_regexp = re.compile(r'http[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
png_stego_xor = 0x61
url_xor = 0xC5
#test_url_for_regexp = "https://pastebin.com/raw/mLem9DGk"

#Change the User-Agent to look less suspicius
headers = {
    'User-Agent': 'cruloader'
}

# RC4 key offset at 0xC
key_offset = 12

# RC4 key size
key_size = 15

# RC4 decrypt the first layer of CruLoader
p = malduck.pe(open(infile, "rb").read(), fast_load=False)
get_rsrc = p.resource(101)
rc4_key = get_rsrc[key_offset:key_offset+key_size]
encrypted = get_rsrc[28:]
decrypted = malduck.rc4(rc4_key, encrypted)

if decrypted[0:2].decode('latin1') != "MZ":
	print("RC4 decryption failed")

# Seems malduck ROL needs data type int according to the documentation
else:
	convert_rol = (decrypted[0:])
	for index,value in enumerate(convert_rol):
		a = malduck.rol(value, 4, bits=8)
		#convert back to bytes for malduck.xor
		b = bytes(chr(a), 'latin1')
		dexor = malduck.xor(0xC5, b)
#		print(dexor)

# Iterate throught the data to find any regexp matches
get_urls = url_regexp.finditer(dexor)

for matched_value in get_urls:
	matched_url = (matched_value.group())
	#URL found in CruLoader sample
	url = matched_url
	r = requests.get(f'{url}', headers=headers)
	first_response = r.content.decode('utf-8')
	#Parse the data from the Pastebin webpage and send a new request
	new_url = first_response
	n = requests.get(f'{new_url}', headers=headers)
	payload = n.content
	# De-XOR payload
	payload = payload
	decrypted = malduck.xor(png_stego_xor, payload)
	# Todo trim de-XOR:ed MZ file. For now I am piping the download payload througth "cut-bytes.py '[4D5A90]':" from Didier Stevens.
	# Write final stego .png payload to disk
	with open ("cruloader_final_payload.bin", 'wb') as o:
		o.write(decrypted)
