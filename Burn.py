from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import OPi.GPIO as GPIO
import MFRC522
import signal
import uuid

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
private_key = ECC.import_key(open('./keys/private_key.pem').read())
signer = DSS.new(private_key, 'fips-186-3')
# This loop keeps checking for chips. If one is near it will get the UID and authenticate
key = [0xff]*6
new_key = [0x5c, 0xc7, 0x5d, 0xf8, 0x0c, 0x21]
access_bits = [0x70, 0xf0, 0xf8, 0x00]
while continue_reading:

    # Scan for cards
    (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)

    # Get the UID of the card
    (status,uid) = MIFAREReader.MFRC522_Anticoll()

    # If we have the UID, continue
    if status == MIFAREReader.MI_OK:
        # Select the scanned tag
        MIFAREReader.MFRC522_SelectTag(uid)

        # Authenticate
        status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, 8, key, uid)

        # Check if authenticated
        if status == MIFAREReader.MI_OK:
            UUID = uuid.uuid4().bytes
            Signature = list(signer.sign(SHA256.new(UUID)))
            MIFAREReader.MFRC522_Write(4, list(UUID))
            MIFAREReader.MFRC522_Write(5, Signature[0:16])
            MIFAREReader.MFRC522_Write(6, Signature[16:32])
            MIFAREReader.MFRC522_Write(9, Signature[32:48])
            MIFAREReader.MFRC522_Write(10, Signature[48:64])

            for sector in range(16):
                MIFAREReader.MFRC522_Write(sector*4 + 3, new_key + access_bits + new_key)
            MIFAREReader.MFRC522_StopCrypto1()
            print('success')
continue_reading = True
