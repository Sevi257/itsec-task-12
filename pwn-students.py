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
iv = binascii.unhexlify("0000000000000000000000000000000000000000000000000000000000000000")
msg = binascii.unhexlify("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")


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
result = ""
for i in range(len(msg)):
    found_same = -1
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    start = read_until(s, b"Do you")

    # Extract the IV and encrypted message from the server response
    if i == 0:
        pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)
        match = pattern.search(start.decode('utf-8'))
        iv = binascii.unhexlify(match.group(1))
        encrypted_message = start.split(b'\n')[1].decode('utf-8').split("(")[0].strip()
        bytes_cipher = binascii.unhexlify(encrypted_message)
        print(len(bytes_cipher))

    # Loop over possible values of j
    for j in range(256):
        test_msg = bytearray(msg)
        test_msg[-i - 17] = j
        final_msg = bytes(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))

        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")

        if "Bad" not in str(response):
            found_same = j
            break

    # Check if a valid value of j was found
    if found_same != -1:
        c8_two = found_same ^ (i + 1) ^ (i + 2)
        result = chr(c8_two) + result

        for k in range(i):
            c8_test = bytearray(result.encode())[-k] ^ (i + 2)
            test_msg = bytearray(msg)
            test_msg[-17 - k] = c8_test
            msg = bytes(test_msg)

        print("New Message:", msg)
        print("Successful", chr(c8_two))
    else:
        print("No valid padding found for iteration", i)

print("Result:", result)

#Es wird gar nix gefunden weil ich etwas beim Padding umrechnen im k loop falsch mache