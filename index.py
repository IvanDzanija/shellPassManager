from re import A
import sys
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
SIZE = 258  # 256 + 2
verifier_text = b"verification"
decrypted = []
masterPassword = None
key = None


def decryptAll():
    readingSize = SIZE + 16 + 16  # encryptedText + iv + tag
    with open("collection.pass", "rb") as f:
        data = f.read()
    offset = 16 + 32  # salt + kdf
    for i in range(offset, len(data), readingSize):
        current = data[i : i + readingSize]
        if len(current) != readingSize:
            continue  # neispravan zapis
        iv = current[0:16]
        encryptedText = current[16 : 16 + SIZE]
        tag = current[16 + SIZE : 16 + SIZE + 16]
        try:
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decText = cipher.decrypt_and_verify(encryptedText, tag)
            link = decText[2 : 2 + decText[0]].decode("ascii")
            password = decText[2 + decText[0] : 2 + decText[0] + decText[1]].decode(
                "ascii"
            )
            decrypted.append((link, password))
        except Exception as e:
            print(e)


def encryptAll():
    salt = get_random_bytes(16)  # Generate a random salt used for the key derivation
    key = scrypt(masterPassword, salt, 32, N=2**20, r=8, p=1)  # Key derivation
    MAC = HMAC.new(key, verifier_text, digestmod=SHA256)
    cipher = AES.new(key, AES.MODE_GCM)
    with open("collection.pass", "wb") as f:
        f.write(salt)
        f.write(MAC.digest())

    # Constant size -> can't fint out lenght of the password
    for i in decrypted:
        toEncrypt = (
            len(i[0]).to_bytes(1, "big")  # Big endian (0x1234 ->(1)0x12 (2)0x34)
            + len(i[1]).to_bytes(1, "big")
            + i[0].encode("ascii")
            + i[1].encode("ascii")
        )
        toEncrypt += get_random_bytes(SIZE - len(toEncrypt))  # Padding

        iv = cipher.nonce
        encryptedText, encryptedTag = cipher.encrypt_and_digest(toEncrypt)
        with open("collection.pass", "ab") as f:
            f.write(iv)
            f.write(encryptedText)
            f.write(encryptedTag)


def init():
    salt = get_random_bytes(16)  # Generate a random salt used for the key derivation
    key = scrypt(masterPassword, salt, 32, N=2**20, r=8, p=1)  # Key derivation

    MAC = HMAC.new(key, verifier_text, digestmod=SHA256)
    with open("collection.pass", "wb") as f:
        f.write(salt)
        f.write(MAC.digest())
    return 0


def checkMasterPassword():
    global key
    # Check if the master password is correct
    with open("collection.pass", "rb") as f:
        stored_salt = f.read(SALT_SIZE)
        stored_verifier = f.read(SHA256.digest_size)

    key = scrypt(masterPassword, stored_salt, 32, N=2**20, r=8, p=1)
    MAC = HMAC.new(key, verifier_text, digestmod=SHA256)
    if MAC.digest() == stored_verifier:
        decryptAll()
        return True
    return False


def updatePassword(address, password):
    for index, value in enumerate(decrypted):
        if value[0] == address:
            decrypted[index] = (address, password)
            print("Updating password!")
            break
    else:
        decrypted.append((address, password))
    encryptAll()
    return 0


def getPassword(address):
    for value in decrypted:
        if value[0] == address:
            return value[1]
    raise Exception("Website not found!")
    return 0


def give_help():
    # Instructions for the user
    print("Usage: ")
    print(
        "init {master password} - Initialize the password manager and creates a new data base"
    )
    print(
        "put {master password} {address} {password} - Add a new password or update an existing one"
    )
    print("get {master password} {address} - Get the password for the given address")
    print("--help - Display this help message")
    return 0


def main():
    global masterPassword
    if sys.argv[1] == "init" and len(sys.argv) == 3:
        masterPassword = sys.argv[2]
        init()
    elif sys.argv[1] == "put" and len(sys.argv) == 5:
        masterPassword = sys.argv[2]
        if checkMasterPassword():
            updatePassword(sys.argv[3], sys.argv[4])
            print("Password successfully loaded/updated")
        else:
            print("Master password is incorrect or integrity check failed")
    elif sys.argv[1] == "get":
        masterPassword = sys.argv[2]
        if checkMasterPassword():
            try:
                print(
                    "Password for website",
                    str(sys.argv[3]),
                    ":",
                    getPassword(sys.argv[3]),
                )
            except Exception as e:
                print(e)
        else:
            print("Master password is incorrect or integrity check failed")
    elif sys.argv[1] == "--help":
        give_help()
    else:
        print("Command not found! For help use --help")


if __name__ == "__main__":
    main()
