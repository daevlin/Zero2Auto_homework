#!/usr/bin/env python3 

from malduck import pe, xor, rc4, rol
import sys
import re
import requests

infile = sys.argv[1]
# URL regexp from https://www.w3resource.com/python-exercises/re/python-re-exercise-42.php
url_regexp = re.compile(r'http[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
png_stego_xor = 0x61
url_xor = 0xC5
s = bytes('', 'latin1')
#Change the User-Agent to look less suspicius
headers = {
    'User-Agent': 'cruloader'
}

# RC4 key offset at 0xC
key_offset = 12

# RC4 key size
key_size = 15

# RC4 decrypt the first layer of CruLoader
p = pe(open(infile, "rb").read(), fast_load=False)
get_rsrc = p.resource('RT_RCDATA')
rc4_key = get_rsrc[key_offset:key_offset+key_size]
encrypted = get_rsrc[28:]
decrypted = rc4(rc4_key, encrypted)
print("[+] Second layer unpacked")

if decrypted[0:2].decode('latin1') != "MZ":
	print("[-] RC4 decryption failed")

# Seems malduck ROL needs data type int according to the documentation
else:
	convert_rol = (decrypted[0:])
	for index,value in enumerate(convert_rol):
		a = rol(value, 4, bits=8)
		#convert back to bytes for malduck.xor
		b = bytes(chr(a), 'latin1')
		dexor = xor(0xC5, b)
		s += dexor

rolxor_data = (s.decode('latin-1'))
		
# Iterate throught the data to find any regexp matches
get_urls = url_regexp.finditer(rolxor_data)

for matched_value in get_urls:
	matched_url = (matched_value.group())
	#URL found in CruLoader sample
	url = matched_url
	print("[+] Found URL in file: " + url) 
	r = requests.get(f'{url}', headers=headers)
	first_response = r.content.decode('utf-8')
	#Parse the data from the Pastebin webpage and send a new request
	new_url = first_response
	print("[+] Making a new HTTP request to the parsed URL: " + new_url) 
	n = requests.get(f'{new_url}', headers=headers)
	payload = n.content
	# De-XOR payload
	payload = payload
	png_marker = bytes('redaolurc', 'latin1')
	m = payload.find(png_marker)
	png_marker_len = len('redaolurc')
	trimmed_file = (payload[m+png_marker_len:])
	decrypted = xor(png_stego_xor, trimmed_file)
	# Write final stego .png payload to disk
	with open ("cruloader_final_payload.bin", 'wb') as o:
		o.write(decrypted)
		print("[+] Wrote final payload to disk")
