#!/usr/bin/env python
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import OPi.GPIO as GPIO
import MFRC522
import signal
import time

continue_reading = True

# Capture SIGINT for cleanup when the script is aborted
def end_read(signal,frame):
    global continue_reading
    continue_reading = False
    GPIO.cleanup()

def toHex(number):
    return "{:02X}".format(number)

# Hook the SIGINT
signal.signal(signal.SIGINT, end_read)

# Create an object of the class MFRC522
MIFAREReader = MFRC522.MFRC522()
public_key = ECC.import_key(open('./keys/public_key.pem').read())
verifier = DSS.new(public_key, 'fips-186-3')
key = [0x5c, 0xc7, 0x5d, 0xf8, 0x0c, 0x21]
# This loop keeps checking for chips. If one is near it will get the UID and authenticate
while continue_reading:
    try:
        # Scan for cards
        (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)

        # Get the UID of the card
        (status,uid) = MIFAREReader.MFRC522_Anticoll()

        # If we have the UID, continue
        if status == MIFAREReader.MI_OK:
            # Print UID
            data = []
            MIFAREReader.MFRC522_SelectTag(uid)
            for i in [8, 9, 10, 13, 14]:

                status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, i, key, uid)
                if status == MIFAREReader.MI_OK:
                    data = data + MIFAREReader.MFRC522_Read(i)
                    
            try:
                verifier.verify(SHA256.new(bytearray(data[0:16])), bytearray(data[16:80]))
                print("VERIFIED " + "".join(map(toHex, uid + data[0:16])))
            except:
                print("UNVERIFIED " + "".join(map(toHex, uid + data[0:16])))

        MIFAREReader.MFRC522_StopCrypto1()
        time.sleep(0.5)
    except:
        print("ERROR")
