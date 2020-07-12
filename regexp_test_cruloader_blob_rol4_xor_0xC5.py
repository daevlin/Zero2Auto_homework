#!/usr/bin/env python3

import re
import malduck
import sys

with open('cruloader_blob_rol4_xor_0xC5.bin', 'rb') as f:
	a = f.read().decode('latin')

url_regexp = re.compile(r'http[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

get_urls = url_regexp.finditer(a)

for matched_value in get_urls:
	matched_url = (matched_value.group())
	print(matched_url)
