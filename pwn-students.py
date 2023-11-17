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
msg = binascii.unhexlify(
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")


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
result = []
for i in range(len(msg)):
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    start = read_until(s, b"Do you")
    print(start)
    ########################################
    # Implement padding oracle attack here #
    ########################################
    # iv erst am Ende verändern
    # shifte msg um 5 bytes nach links und füge den wert hinzu mit brute force
    # msg slicen und am ende
    # extract the encrypted message
    # The string containing the encrypted message and IV

    # Anfangen beim 15. Byte
    # 16 Byte Block Länge
    # Extend indem man den letzten Block einfach abschneidet
    # P12 = 0x01 xor C8 (ursprüngliches Byte encrypted) xor C'8 (bruteforced byte for 0x01)
    # C8'' for 0x02 = C8 xor P12 xor 0x02 (variable)
    # P11 = 0x02 xor C7' xor C7 og

    pattern = re.compile(r'IV was (.+?)\)\n\n', re.DOTALL)

    match = pattern.search(start.decode('utf-8'))
    iv = binascii.unhexlify(match.group(1))
    encrypted_message = start.split(b'\n')[1].decode('utf-8')
    encrypted_message = encrypted_message.split("(")[0].strip()
    bytes_cipher = binascii.unhexlify(encrypted_message)
    print(len(bytes_cipher))
    test_msg = msg
    # Hier die Variable für den Loop
    for j in range(256):
        s = socket.socket()
        s.connect(("itsec.sec.in.tum.de", 7023))
        read_until(s, b"Do you")
        test_msg = bytearray(msg)
        #print("Test_msg: ", binascii.hexlify(test_msg))
        test_msg[len(test_msg) - i - 16] = j
       # print("New Test_msg: ", binascii.hexlify(test_msg))
        final_msg = bytes(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))
        #print("Final Message: ", binascii.hexlify(final_msg))
        s.send(binascii.hexlify(iv) + b"\n")
        s.send(binascii.hexlify(final_msg) + b"\n")
        response = read_until(s, b"\n")
        if "Bad" not in str(response):
            # Jetzt haben wir C'8 herausgefunden
            # P12 = 0x01 xor C8 (ursprüngliches Byte encrypted) xor C'8 (bruteforced byte for 0x01)
            # C8'' for 0x02 = C8 xor P12 xor 0x02 (variable)
            # c8_ = c'8 ; encrypted_msg[15-i] = c8 ; hexformat of i
            if encrypted_message == binascii.hexlify(final_msg).decode():
                print("Same Same")
            else:
                #print("Hello")
                c8_ = bytearray(final_msg)[len(final_msg) - i - 16]
                # P12
                og_message = bytes(a ^ b ^ c for a, b, c in zip(binascii.unhexlify(encrypted_message), bytearray(c8_),
                                                                i.to_bytes(1, "little")))
                # Vielleicht muss man des anders machen und mit Nullen auffüllen also z.B. 0x02
                # Nach der ersten Runde muss halt dann angepasst werden also der Nachrichtenstring für i + 1
                # check out if it really comes out to 0x01 and not the real padding
                # C8'' for 0x02 = C8 xor P12 xor 0x02 (variable)
                test = bytes(a ^ b ^ c for a, b, c in zip(binascii.unhexlify(encrypted_message), og_message,
                                                          (i + 1).to_bytes(1, "big")))
                result.append(og_message)
                #print("Test: ", test)
                print("Succesful ", og_message)
                break
