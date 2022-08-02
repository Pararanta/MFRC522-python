from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
import OPi.GPIO as GPIO
import MFRC522
import signal
import uuid
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
private_key = ECC.import_key(open('./keys/private_key.pem').read())
signer = DSS.new(private_key, 'fips-186-3')
# This loop keeps checking for chips. If one is near it will get the UID and authenticate
key = [0xff]*6
new_key = [0x5c, 0xc7, 0x5d, 0xf8, 0x0c, 0x21]
access_bits = [0x07, 0x87, 0x8F, 0xFF]
while continue_reading:

    # Scan for cards
    (status,TagType) = MIFAREReader.MFRC522_Request(MIFAREReader.PICC_REQIDL)

    # Get the UID of the card
    (status,uid) = MIFAREReader.MFRC522_Anticoll()

    # If we have the UID, continue
    if status == MIFAREReader.MI_OK:
        # Select the scanned tag
        MIFAREReader.MFRC522_SelectTag(uid)
        UUID = uuid.uuid4().bytes
        data = map(ord, list(UUID)) + map(ord, list(signer.sign(SHA256.new(UUID))))
        order = [8, 9, 10, 13, 14]
        for i in range(5):
            status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, order[i], key, uid)
            if status == MIFAREReader.MI_OK:
                MIFAREReader.MFRC522_Write(order[i], data[(i*16):((i+1)*16)])

        for sector in range(0, 16):
            status = MIFAREReader.MFRC522_Auth(MIFAREReader.PICC_AUTHENT1A, sector*4 + 3, key, uid)
            if status == MIFAREReader.MI_OK:
                MIFAREReader.MFRC522_Write(sector*4 + 3, new_key + access_bits + new_key)
        
        MIFAREReader.MFRC522_StopCrypto1()
        print("DONE " + "".join(map(toHex, uid + data[0:16])))
        time.sleep(4)