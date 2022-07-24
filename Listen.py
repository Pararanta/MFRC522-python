#!/usr/bin/env python
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import OPi.GPIO as GPIO
import MFRC522
import signal

continue_reading = True

# Capture SIGINT for cleanup when the script is aborted
def end_read(signal,frame):
    global continue_reading
    continue_reading = False
    GPIO.cleanup()

# Hook the SIGINT
signal.signal(signal.SIGINT, end_read)

# Create an object of the class MFRC522
MIFAREReader = MFRC522.MFRC522()
public_key = ECC.import_key(open('./keys/public_key.pem').read())
verifier = DSS.new(public_key, 'fips-186-3')
# This loop keeps checking for chips. If one is near it will get the UID and authenticate
while continue_reading:
    
    # Scan for cards    
    (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)
    
    # Get the UID of the card
    (status,uid) = MIFAREReader.MFRC522_Anticoll()

    # If we have the UID, continue
    if status == MIFAREReader.MI_OK:

        # This is the default key for authentication
        key = [0x5c, 0xc7, 0x5d, 0xf8, 0x0c, 0x21]
        # Select the scanned tag
        MIFAREReader.MFRC522_SelectTag(uid)

        # Authenticate
        status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, 8, key, uid)

        # Check if authenticated
        if status == MIFAREReader.MI_OK:
            UUID = MIFAREReader.MFRC522_Read(0);
            Signature = MIFAREReader.MFRC522_Read(1) + MIFAREReader.MFRC522_Read(2) + MIFAREReader.MFRC522_Read(5) + MIFAREReader.MFRC522_Read(6);
            try:
                verifier.verify(SHA256.new(bytes(UUID)), bytes(Signature))
                print('verified ' + ''.join(format(x, '02x') for x in UUID))
            except:
                print('unverified ' + ''.join(format(x, '02x') for x in UUID))
            MIFAREReader.MFRC522_StopCrypto1()

