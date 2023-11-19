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


def find_byte(s, msg, encrypted_message, i):
    """Finds the byte at position `i` in the original message"""
    for j in range(256):
        test_msg = bytearray(msg)
        test_msg[-i - 17] = j

        final_msg = bytes(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))

        if i >= 16:
            final_msg = final_msg[:-16]
        if i >= 32:
            final_msg = final_msg[:-16]

        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")

        if "Bad" not in str(response):
            return j

    return None

def main():
    iv = binascii.unhexlify("0000000000000000000000000000000000000000000000000000000000000000")
    msg = binascii.unhexlify("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

    result = ""
    found_same = -1

    for i in range(len(msg)):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))

        start = read_until(s, b"Do you")

        if i == 0:
            pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)
            match = pattern.search(start.decode('utf-8'))
            iv = binascii.unhexlify(match.group(1))
            encrypted_message = start.split(b'\n')[1].decode('utf-8')
            encrypted_message = encrypted_message.split("(")[0].strip()

        c8_ = find_byte(s, msg, encrypted_message, i)

        if c8_ is not None:
            og_message = (i + 1) ^ c8_
        else:
            c8_ = found_same
            og_message = (i + 1) ^ c8_

        result += chr(og_message)

        for k in range(i + 1):
            c8_test = bytearray(result.encode())[-k] ^ (i + 2)
            test2_msg = bytearray(msg)
            test2_msg[-17 - k] = c8_test
            msg = bytes(test2_msg)

        print("Result: ", result)

if __name__ == "__main__":
    main()