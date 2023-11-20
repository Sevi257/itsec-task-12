import binascii
import re
import socket
import telnetlib

# First take a look at the server. Afterwards, comment out the next four lines...
# t = telnetlib.Telnet("itsec.sec.in.tum.de", 7023)
# t.interact()
# import sys
# sys.exit(0)

# If you have done that, copy over a hexlified message + IV over to this script (replacing the zeros)
iv = binascii.unhexlify("76b323c4c5bca0010db836fed6a8c76e")
msg = binascii.unhexlify(
    "ee5a3f0c9984104ffc7652ee97ca897ad4b13dc161919364ca3b4cedc0fee8462fbf5f5195592ab622774c85f6442679b40637de54c747a8ca65bc681f5e7a93")


def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf


# The server allows you to process a single message with each connection.
# Connect multiple times to decrypt the (IV, msg) pair above byte by byte.
print(len(msg))
print(len(iv))
result = []
# An die erste Stelle im result array kommt auch das erste byte also immer appenden
found_same = -1
for i in range(len(msg)):
    found = False
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    # s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
    ########################################
    if i == 0:
        pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)
        match = pattern.search(start.decode('utf-8'))
        iv = binascii.unhexlify(match.group(1))
        encrypted_message = start.split(b'\n')[1].decode('utf-8')
        encrypted_message = encrypted_message.split("(")[0].strip()
        bytes_cipher = binascii.unhexlify(encrypted_message)
        msg = binascii.unhexlify(encrypted_message)

    print(result)
    for j in range(256):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))
        # s.connect(("localhost", 1024))

        read_until(s, b"Do you")
        test_msg = bytearray(msg)
        test_msg[-i - 17] ^= j
        # Change test_msg slightly

        test_msg[-i - 17 - 1] = 0xFF
        test_msg[-i - 17 - 2] = 0xFF

        for k in range(i):
            new_byte = result[k] ^ (i + 1)
            test_msg[-17 - k] ^= new_byte
        final_msg = test_msg
        if i >= 16:
            final_msg = test_msg[:-16]
        if i >= 32:
            final_msg = test_msg[:-16]
        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")
        if "Bad" not in str(response):
            og_message = (i + 1) ^ j
            result.append(og_message)

            # Append the final result outside the loop
            print("Succesful ", chr(og_message))
            break
flag = ""
for char in result:
    flag = chr(char) + flag
print(flag)