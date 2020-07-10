#!/usr/bin/env python3

#Todo brute XOR instead of static hex value
#Todo 2 trim de-XOR:ed MZ file

import requests
import malduck

url = 'http://i.ibb.co/KsfqHym/PNG-02-Copy.png'

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36'
}

r = requests.get(f'{url}', headers=headers)

response = r.content

key = 0x61
payload = response
decrypted = malduck.xor(key, payload)

with open ("test.bin", 'wb') as o:
	o.write(decrypted)

