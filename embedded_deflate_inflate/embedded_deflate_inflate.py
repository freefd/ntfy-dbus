#!/usr/bin/env pyrhon3
''' Encode-Decode test for embedded data '''

import zlib
import base64
import sys
import hashlib

if not len(sys.argv) > 1:
    print('Please provide a file path')
    sys.exit(1)

INITIAL_CHECKSUM = None
DECOMPRESSED_CHECKSUM = None

print('FILE => COMPRESSED => BASE64')
try:
    print(f'  [=] {sys.argv[1]} >> FILE')
    with open(sys.argv[1], 'rb') as data:
        data_file=data.read()
except IOError as open_error:
    print(f'  [!] File input failed: {open_error}')
    sys.exit(1)

try:
    INITIAL_CHECKSUM = hashlib.sha256(data_file).hexdigest()
    print('  [=] FILE >> SHA256')
    print(f'  [=] SHA256: {INITIAL_CHECKSUM}')
except:
    print('  [!] Checksum calculation failed')
    sys.exit(1)

try:
    print('  [+] FILE >> COMPRESSED')
    zlibbed_string = zlib.compress(data_file)
    compressed_string = zlibbed_string[2:-4]
except:
    print('  [!] File compression failed')
    sys.exit(1)

try:
    print('  [+] COMPRESSED >> BASE64')
    deflate_b64 = base64.b64encode(compressed_string)
except base64.binascii.Error as b64_encode_error:
    print(f'  [!] BASE64 encoding failed: {b64_encode_error}')
    sys.exit(1)

try:
    print(f'  [+] BASE64 >> {sys.argv[1]}.b64')
    with open(f'{sys.argv[1]}.b64', 'w', encoding='utf8') as b64:
        b64.write(deflate_b64.decode())
except (IOError, UnicodeDecodeError) as open_error:
    print(f'  [!] BASE64 output failed: {open_error}')
    sys.exit(1)

print ('\nBASE64 => DECOMPRESSED => FILE')

try:
    print(f'  [=] {sys.argv[1]}.b64 >> BASE64')
    with open(f'{sys.argv[1]}.b64', 'r', encoding='utf8') as data:
        b64_string=data.read()
except IOError as open_error:
    print(f'  [!] BASE64 read test failed: {open_error}')
    sys.exit(1)

try:
    print ('  [+] BASE64 >> DECOMPRESSED')
    b64_decoded_data = base64.b64decode(b64_string)
except base64.binascii.Error as b64_decode_error:
    print(f'  [!] BASE64 decode test failed: {b64_decode_error}')
    sys.exit(1)

try:
    print('  [+] DECOMPRESSED >> FILE')
    data_file = zlib.decompress(b64_decoded_data , -15)
except:
    print('  [!] Decompression test failed')

try:
    DECOMPRESSED_CHECKSUM = hashlib.sha256(data_file).hexdigest()
    print('  [=] FILE >> SHA256')
    print(f'  [=] SHA256: {DECOMPRESSED_CHECKSUM}')
except:
    print('  [!] Checksum Calculation failed')
    sys.exit(1)

try:
    print(f'  [+] FILE >> decompressed_{sys.argv[1]}')
    with open(f'decompressed_{sys.argv[1]}', 'wb') as data:
        data.write(data_file)
except IOError as open_error:
    print(f'  [!] File write failed: {open_error}')

print (f'\nCHECKSUM: {sys.argv[1]} <-> decompressed_{sys.argv[1]}')
if INITIAL_CHECKSUM == DECOMPRESSED_CHECKSUM:
    print(f'  [=] Checksums are equal: {INITIAL_CHECKSUM}')
else:
    print(f'  [!] Checksums are different:\n\t{INITIAL_CHECKSUM}\n\t{DECOMPRESSED_CHECKSUM}')
