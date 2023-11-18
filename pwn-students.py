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
    s = socket.socket()
    s.connect(("itsec.sec.in.tum.de", 7023))
    #s.connect(("localhost", 1024))
    start = read_until(s, b"Do you")
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
        #print("Test_msg: ", binascii.hexlify(test_msg))
        # Hier wird das i-letzte Byte gebruteforced
        test_msg[len(test_msg) - i - 16] = j
       # print("New Test_msg: ", binascii.hexlify(test_msg))
        # TODO -> Wieso nochmal xor eigentlich? Doch stimmt ich schicke ja nur final message des wird dann serverside bearbeitet und dann ist padding correct aber ich brauche j

        final_msg = bytes(a ^ b for a, b in zip(test_msg, binascii.unhexlify(encrypted_message)))
        #print("Final message sent: ", binascii.hexlify(final_msg))
        #print("Encrypted message : ", encrypted_message)
        #print("Test Message test : ", binascii.hexlify(test_msg))
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
                #man muss xoren und c8 wird einfach zu dem Index in der encrypted message
                c8_ = j
                og_cipher_byte = bytes.fromhex(encrypted_message)[len(encrypted_message)//2-16-i]
                print("C8_       : ", hex(c8_))
                print("OG Cypher : ", og_cipher_byte)
                # P12 vielleicht muss die 1 noch mit Nullen davor sein
                # Nicht mit sich selbst xoren sondern mit Nullen
                # weil c8 muss ja an die richtige stelle
                og_message = (i+1) ^ c8_ ^ og_cipher_byte
                # Vielleicht muss man des anders machen und mit Nullen auffüllen also z.B. 0x02
                # Nach der ersten Runde muss halt dann angepasst werden also der Nachrichtenstring für i + 1
                # check out if it really comes out to 0x01 and not the real padding
                # C8'' for 0x02 = C8 xor P12 xor 0x02 (variable)
                # Man muss C8'' noch anpassen dann immer
                # Einerseits kann man wirklich nur auf Bytes arbeiten
                # auch dass i+1 to bytes noch der Länge anpassen oder halt einfach da bei der Message einfügen
                #dann mit einem for loop jedes Byte anpassen
                for k in range(i+1):
                    # Man muss die alten Bytes rausziehen und nochmal mit i xoren
                    # X[15] = P’1[15] ⊕ C2[15] ⊕ P3[15] = 0x02 ⊕ C2[15] ⊕ P3[15] where C2[15] et P3[15] are known
                    # Ich muss jedes Byte aus der Message xoren mit dem zugehörigen Klartext aus dem Result array
                    # und zusätzlich noch mit dem i und dann zurückschreiben
                    # nehme das erste Byte von hinten aus dem msg-array
                    # anstatt j nehme das k-te Byte von hinten
                    if i == 0:
                        c8_two = j ^ (i+1) ^ (i + 2)
                        #print("C82: ", c8_two)
                        result += chr(og_message)
                        test2_msg = bytearray(msg)
                        test2_msg[len(test2_msg) - 16 - i] = c8_two
                        msg = bytes(test2_msg)
                    else:
                        c8_test = bytearray(msg)[len(msg)-16-k] ^ (i+1) ^ (i+2)
                        msg = bytearray(msg)
                        msg[len(msg)-16-k] = c8_test
                        msg = bytes(msg)

                print("New Message: " , msg)
                #print("Len MSG: ", len(msg))
                # Man muss den Cyphertext anpassen
                print("Succesful ", og_message)
                break
    print("Result: ", result)