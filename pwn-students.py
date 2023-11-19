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
found_same = -1
for i in range(len(msg)):
    found = False
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    #s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
    ########################################
    if i == 0:
        pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)

        match = pattern.search(start.decode('utf-8'))
        iv = binascii.unhexlify(match.group(1))
        encrypted_message = start.split(b'\n')[1].decode('utf-8')
        encrypted_message = encrypted_message.split("(")[0].strip()
        bytes_cipher = binascii.unhexlify(encrypted_message)
        print(len(bytes_cipher))
        test_msg = msg
    print(bytearray(result.encode()))
    for j in range(256):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))
        #s.connect(("localhost", 1024))

        read_until(s, b"Do you")
        test_msg = bytearray(msg)
        test_msg[-i-17] = j
        final_msg = bytearray(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))
        if i >= 16:
            final_msg = final_msg[:-16]
        if i >= 32:
            final_msg = final_msg[:-16]
        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")
        if "Bad" not in str(response):
            if encrypted_message == binascii.hexlify(final_msg).decode():
                found_same = j
                print("Same Same")
            else:
                found = True
                og_message = (i+1) ^ j
                c8_test = j
                result += chr(og_message)
                if i == 0:
                    c8_two = j ^ 1 ^ (i + 2)
                    test2_msg = bytearray(msg)
                    test2_msg[- 17 - i] = c8_two
                    msg = bytes(test2_msg)
                else:
                    for k in range(1, i + 1):
                        c8_test = bytearray(result.encode())[- k] ^ (i + 2)
                        print(f"k: {k}, Byte: {bytearray(result.encode())[-k]}, P2'': {(i + 2)}, C8 Test: {c8_test}")
                        test2_msg = bytearray(msg)
                        test2_msg[- 17 - k] = c8_test
                        msg = bytes(test2_msg)

                # Append the final result outside the loop

                print("New Message: ", binascii.hexlify(msg))
                print("Succesful ", chr(og_message))
                break
    if not found:
        # Das Padding ist richtig
        found = True
        c8_ = found_same
        og_message = (i + 1) ^ c8_
        result += chr(og_message)
        if i == 0:
            c8_two = found_same ^ 1 ^ (i + 2)
            test2_msg = bytearray(msg)
            test2_msg[- 17 - i] = c8_two
            msg = bytes(test2_msg)
        else:
            for k in range(i + 1):
                #Bei Result wird falsch geaccesed
                # Muss so angepasst werden dass des Ergebnis 0x02 ist
                c8_test = bytearray(result.encode())[-k] ^ (i + 2)
                print(f"k: {k}, Byte: {bytearray(result.encode())[-k]}, P2'': {(i + 2)}, C8 Test: {c8_test}")
                test2_msg = bytearray(msg)
                test2_msg[- 17 - k] = c8_test
                msg = bytes(test2_msg)

        # Append the final result outside the loop

        print("New Message: ", binascii.hexlify(msg))
        # print("Len MSG: ", len(msg))
        # Man muss den Cyphertext anpassen
        print("Succesful ", chr(og_message))

    print("Result: ", result)