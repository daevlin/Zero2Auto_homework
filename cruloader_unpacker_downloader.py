#!/usr/bin/env python3
# WHat? Who needs error handling?

import malduck
import sys
import re
import requests

infile = sys.argv[1]
url_regexp = re.compile(r'\b(http|https)+://+((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}b', re.I)
png_stego_xor = 0x61
url_xor = 0xC5

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

convert_rol = (decrypted)

# Seems malduck ROL needs data type int according to the documentation
for index,value in enumerate(convert_rol):
	 a = malduck.rol(value, 4, bits=8)
	 
dexor = malduck.xor(url_xor, a)

# Iterate throught the data to find any regexp matches
get_urls = url_regexp.finditer(dexor)

for matched_value in get_urls:
	matched_url = (matched_value.group())

#URL found in CruLoader sample
url = matched_url

#Change the User-Agent to look less suspicius
headers = {
    'User-Agent': 'cruloader'
}

r = requests.get(f'{url}', headers=headers)

first_response = r.content.decode('utf-8')

#Parse the data from the Pastebin webpage and send a new request
new_url = first_response
n = requests.get(f'{new_url}', headers=headers)
payload = n.content

# De-XOR payload
payload = payload
decrypted = malduck.xor(png_stego_key, payload)

# Todo trim de-XOR:ed MZ file. For now I am piping the download payload througth "cut-bytes.py '[4D5A90]':" from Didier Stevens.

# Write final stego .png payload to disk
with open ("final_payload.bin", 'wb') as o:
	o.write(decrypted)
