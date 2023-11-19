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
    found = False
    found_same = -1

    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    #s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
    ########################################
    # Implement padding oracle attack here #
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

    # Hier die Variable für den Loop
    # C'i-1 = Ci-1 ⊕ 00000001 ⊕ 0000000X | Ci

    for j in range(256):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))
        #s.connect(("localhost", 1024))

        read_until(s, b"Do you")
        test_msg = bytearray(msg)
        test_msg[-i-17] = j
       # print("New Test_msg: ", binascii.hexlify(test_msg))
        # TODO -> Wieso nochmal xor eigentlich? Doch stimmt ich schicke ja nur final message des wird dann serverside bearbeitet und dann ist padding correct aber ich brauche j
        final_msg = bytes(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))
        if i >= 16:
            final_msg = final_msg[:-16]
        if i >= 32:
            final_msg = final_msg[:-16]
        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")
        if "Bad" not in str(response):
            # Jetzt haben wir C'8 herausgefunden
            # P12 = 0x01 xor C8 (ursprüngliches Byte encrypted) xor C'8 (bruteforced byte for 0x01)
            # C8'' for 0x02 = C8 xor P12 xor 0x02 (variable)
            # c8_ = c'8 ; encrypted_msg[15-i] = c8 ; hexformat of i
            if encrypted_message == binascii.hexlify(final_msg).decode():
                found_same = j
                print("Same Same")
            else:
                found = True
                c8_ = j
                og_cipher_byte = bytes.fromhex(encrypted_message)[-17-i]
                print("C8_       : ", hex(c8_))
                print("OG Cypher : ", og_cipher_byte)
                og_message = (i+1) ^ c8_
                result += chr(og_message)
                for k in range(i + 1):
                    if i == 0:
                        c8_two = j ^ (k + 1) ^ (i + 2)
                        test2_msg = bytearray(msg)
                        test2_msg[- 17 - i] = c8_two
                        msg = bytes(test2_msg)
                    else:
                        # Brauche das orginalByte nicht das aus der msg
                        c8_test = bytearray(result.encode())[- k] ^ (i + 2)
                        print(f"k: {k}, Byte: {bytearray(result.encode())[-k]}, P2'': {(i + 2)}, C8 Test: {c8_test}")
                        test2_msg = bytearray(msg)
                        test2_msg[- 17 - k] = c8_test
                        msg = bytes(test2_msg)

                # Append the final result outside the loop

                print("New Message: ", binascii.hexlify(msg))
                #print("Len MSG: ", len(msg))
                # Man muss den Cyphertext anpassen
                print("Succesful ", chr(og_message))
                break
    if not found:
        # Das Padding ist richtig
        found = True
        c8_ = found_same
        og_message = (i + 1) ^ c8_
        result += chr(og_message)

        for k in range(i + 1):
            if i == 0:
                c8_two = found_same ^ (k + 1) ^ (i + 2)
                test2_msg = bytearray(msg)
                test2_msg[- 17 - i] = c8_two
                msg = bytes(test2_msg)
            else:
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

#Es wird gar nix gefunden weil ich etwas beim Padding umrechnen im k loop falsch mache
# Alles abschneiden bei i == 16