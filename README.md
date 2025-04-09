# 🔐 Encrypted Password Vault

A lightweight command-line password manager written in Python. Passwords are encrypted and stored in a secure text file using AES-GCM encryption with key derivation via a user-provided master password.

---

## 📦 Requirements

- Python 3
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) library

To install the required dependency, run:

```bash
pip3 install pycryptodome
```

---

## 🚀 Usage

Every command is available with the `--help` flag:

```bash
python3 ./index.py --help
```

### 🛠 Initialization

Initializes a new database (overwrites any existing file):

```bash
python3 ./index.py init {MasterPassword}
```

---

### ➕ Add a New Entry

Adds a new record to the database. If an entry for the same website already exists, the old password is replaced:

```bash
python3 ./index.py put {MasterPassword} {WebsiteLink} {Password}
```

---

### 🔍 Retrieve an Entry

Retrieves a stored password for the specified website:

```bash
python3 ./index.py get {MasterPassword} {WebsiteLink}
```

---

## 🔎 How It Works

### Database Initialization

When initializing the database, the following data is written:

```
[16B salt] + [32B verification HMAC]
```

- A **random 16-byte salt** is generated.
- A **key** is derived from the `{MasterPassword}` and this salt.
- A **verification HMAC** is computed using the derived key and a constant verification string.
- This allows checking if the correct `{MasterPassword}` is provided in future sessions, without decrypting anything else.
- If the password is incorrect, verification fails, and no further decryption takes place.

---

### Data Structure for Stored Passwords

Each database entry is structured and encrypted as follows:

```
[16B IV] + [16B Authentication Tag] + [x entries * 258B per entry]
```

- Each entry consists of:
  - 1B: Length of the website link (max 128)
  - 1B: Length of the password (max 128)
  - Up to 256B: Website link + Password (padded to fixed 258B per entry)
- All entries are encrypted together into a single ciphertext using AES-GCM.
- A **new IV (Initialization Vector)** is generated for each encryption.
- The entire encrypted data includes a **verification tag** to ensure integrity.

This design ensures:
- Entries are indistinguishable — attackers cannot locate or identify specific records.
- The number of passwords is the only visible metadata.
- Tampering with entries will invalidate the authentication tag and be detected.
- It's impossible to inject new entries without knowing the master password.

---

### Decryption Process

To retrieve data:
1. Load the salt and verification HMAC.
2. Derive the key again from the entered `{MasterPassword}` and salt.
3. Verify the HMAC.
4. If valid, use the IV and key to decrypt the ciphertext.
5. Parse every 258-byte block:
   - First byte: Length of the website link.
   - Second byte: Length of the password.
   - Remaining bytes: Website link + password.
6. After modification, the whole database is re-encrypted with a new IV.

---

## ✅ Security Notes

- The database cannot be decrypted or modified without the correct master password.
- No plaintext passwords are ever stored.
- The padding and encryption strategy hides structural information.
- AES-GCM ensures both confidentiality and authenticity.

---

## 📁 Example

```bash
python3 ./index.py init myStrongMasterPass123
python3 ./index.py put myStrongMasterPass123 example.com myPassword!
python3 ./index.py get myStrongMasterPass123 example.com
```

---

## 📄 License

MIT License
