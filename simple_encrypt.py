#!/usr/bin/env python

from Crypto.Cipher import AES
from pathlib import PurePath

import sys
import os
import base64

src_path = sys.argv[1]
base64_key = sys.argv[2]

src_fullpath = PurePath(src_path)
dst_path = src_fullpath.with_name('encrypted_'+src_fullpath.name)

key = base64.b64decode(base64_key)
iv = bytearray([0] * 12)
cipher = AES.new(key, AES.MODE_GCM, iv)

with open(src_path,"rb") as in_stream:
    encrypted_data = cipher.encrypt(in_stream.read())
    with open(dst_path, "wb") as out_stream:
        out_stream.write(encrypted_data)