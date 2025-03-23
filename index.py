import sys
from Crypto.Cipher import AES
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
    with open("collection.pass", "rb") as f:
        data = f.read()
    offset = 16 + 32  # salt + kdf
    data = data[offset:]
    if len(data) < (258 + 16 + 16):
        print("Database empty or corrupted!")
        return
    iv = data[0:16]
    tag = data[16:32]
    encryptedText = data[32:]
    if len(encryptedText) % SIZE != 0:
        print("Data corrupted!")
        return
    try:
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decText = cipher.decrypt_and_verify(encryptedText, tag)
        for i in range(0, len(decText), SIZE):
            link = decText[i + 2 : i + 2 + decText[i]].decode("ascii")
            password = decText[
                i + 2 + decText[i] : i + 2 + decText[i] + decText[i + 1]
            ].decode("ascii")
            decrypted.append((link, password))
    except Exception as e:
        print(e)


def encryptAll():
    salt = get_random_bytes(16)  # Generate a random salt used for the key derivation
    key = scrypt(masterPassword, salt, 32, N=2**20, r=8, p=1)  # Key derivation
    MAC = HMAC.new(key, verifier_text, digestmod=SHA256)
    with open("collection.pass", "wb") as f:
        f.write(salt)
        f.write(MAC.digest())

    # Constant size -> can't fint out lenght of the password
    allData = bytes()
    for i in decrypted:
        toEncrypt = (
            len(i[0]).to_bytes(1, "big")  # Big endian (0x1234 ->(1)0x12 (2)0x34)
            + len(i[1]).to_bytes(1, "big")
            + i[0].encode("ascii")
            + i[1].encode("ascii")
        )
        toEncrypt += get_random_bytes(SIZE - len(toEncrypt))  # Padding
        allData += toEncrypt

    cipher = AES.new(key, AES.MODE_GCM)
    iv = cipher.nonce
    encryptedText, encryptedTag = cipher.encrypt_and_digest(allData)
    with open("collection.pass", "ab") as f:
        f.write(iv)
        f.write(encryptedTag)
        f.write(encryptedText)


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
