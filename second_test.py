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
'''print(len(msg))
print(len(iv))
result = [0]*40
result[0] = 1
result[1] = 10
result[2] = 10
result[3] = 125
hexlist = "0123456789abcdef"
# An die erste Stelle im result array kommt auch das erste byte also immer appenden
found_same = -1
i = 0
counter = 0
while i < len(msg):
    if i == 16 or i == 32:
        counter += 1

    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    # s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
    ########################################
    if i == 0:
        pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)
        match = pattern.search(start.decode('utf-8'))
        #iv = binascii.unhexlify(match.group(1))
        encrypted_message = start.split(b'\n')[1].decode('utf-8')
        encrypted_message = encrypted_message.split("(")[0].strip()
        bytes_cipher = binascii.unhexlify(encrypted_message)
        #msg = binascii.unhexlify(encrypted_message)
        print(encrypted_message)
    if i > 3 or counter != 0:
        if i == 40:
            break
        for j in range(256):
            if (47 < (i % 16 + 1) ^ j < 58) or (96 < (i % 16 + 1) ^ j < 103):
                s = socket.socket()
                s.connect(("itsec.sec.in.tum.de", 7023))
                test_msg = bytearray(msg)
                read_until(s, b"Do you")
                test_msg[-i - 17] ^= j
                print("TestMessage: ", binascii.hexlify(test_msg))
                #Es werden die falschen bytes verxored
                for k in range(i):
                    new_byte = result[k] ^ (i % 16 + 1)
                    if i >14:
                        print("Gewählter Wert: ", result[k], " an der Stelle ", -17-k)
                    test_msg[-17 - k] ^= new_byte
                #test_msg[-i - 17 - 1] = 0xFF
                #test_msg[-i - 17 - 2] = 0xFF
                for l in range(counter):
                    test_msg = test_msg[:-16]
                final_msg = test_msg
                print(binascii.hexlify(final_msg))
                print(result)
                s.send(binascii.hexlify(iv) + b"\n")
                s.send(binascii.hexlify(final_msg) + b"\n")
                response = read_until(s, b"\n")
                if "Bad" not in str(response):
                    og_message = (i%16 + 1) ^ j
                    result[i] = og_message
                    print("Succes: ", chr(og_message))
                    # Append the final result outside the loop
                    break
    i += 1
'''
print(len(msg))
print(len(iv))
result = []
result.append(1)
result.append(10)
result.append(10)
result.append(125)
hexlist = "0123456789abcdef"
# An die erste Stelle im result array kommt auch das erste byte also immer appenden
found_same = -1
blockcounter = 0
i = 0
counter = 0
while i < len(msg):
    if i == 16:
        i = 0
        counter += 1
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    # s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
    ########################################
    if i == 0 and counter == 0:
        pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)
        match = pattern.search(start.decode('utf-8'))
        iv = binascii.unhexlify(match.group(1))
        encrypted_message = start.split(b'\n')[1].decode('utf-8')
        encrypted_message = encrypted_message.split("(")[0].strip()
        bytes_cipher = binascii.unhexlify(encrypted_message)
        msg = binascii.unhexlify(encrypted_message)
    if i > 3 or counter != 0:
        if len(result) >= 40:
            break
        for j in range(256):
            if (47 < (i + 1) ^ j < 58) or (96 < (i + 1) ^ j < 103):
                s = socket.socket()
                s.connect(("itsec.sec.in.tum.de", 7023))
                test_msg = bytearray(msg)
                read_until(s, b"Do you")
                for l in range(counter):
                    test_msg = test_msg[:-16]
                test_msg[-i - 17] ^= j
                for k in range(i):
                    try:
                        new_byte = result[k + counter * 16] ^ (i + 1)
                        test_msg[-17 - k] ^= new_byte
                    except Exception:
                        print(f"K: {k}, Counter: {counter * 16}, length: {len(result)}")
                test_msg[-i - 17 - 1] = 0xFF
                test_msg[-i - 17 - 2] = 0xFF
                final_msg = test_msg
                # print(binascii.hexlify(final_msg))

                s.send(binascii.hexlify(iv) + b"\n")
                s.send(binascii.hexlify(final_msg) + b"\n")
                response = read_until(s, b"\n")
                if "Bad" not in str(response):
                    og_message = (i + 1) ^ j
                    result.append(og_message)
                    print("Succes: ", chr(og_message))
                    # Append the final result outside the loop
                    break
    i += 1

f = "flag{"
flag = ""
for char in result:
    flag = chr(char) + flag
print(f + flag)
f = "flag{"
flag = ""
for char in result:
    flag = chr(char) + flag
print(f + flag)