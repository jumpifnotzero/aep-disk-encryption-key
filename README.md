# Keyper HSM key mapping
This project provides documentation and tools supporting the analysis of the Keyper HSM's keymap file.

### Keymap file
The keymap file (keymap.db) contains an entry for every key stored in the HSM. The machine file describes the location of the keymap file for a specific slot/token.

The keymap file follows a CSV-format, without header row, and with character-string values enclosed by '@'. Of the 49 columns, the data includes:
- Encrypted data in hexadecimal (Column 3)
- PKCS#11 key type (Column 6)
- Label (Column 11)
- Modulus in hexadecimal (Column 35)
- Exponent in hexadecimal (Column 36)

### Disk Encryption Key
The keymap file contains data encrypted using Triple-DES. The Disk Encryption Key (DEK) is derived from the User PIN using PBKDF2 with 10 iterations and dkLen of 21 to produce 168 bits output; the equivalent of 3 independent 56-bit keys. The salt provided to the PBKDF2 function is the SHA-1 hash of the PIN padded by fixed 16-byte sequence on both sides:
```
  salt = sha1 ( 0x5555555555555555AAAAAAAAAAAAAAAA | pin | 0x5555555555555555AAAAAAAAAAAAAAAA )
```

Parity bits can be added to produce a 192-bit key-value that can be imported into relevant libraries.

### Encrypted data
Decrypting the value in third column reveals the following information:
```
  column-3 = 0xFFFFFFFF | ???? | key-size | identifier | key-policy
```
Question marks represent bytes of unknown significance.

The identifier is the value transmitted over-the-wire to the HSM to identify this key and is further encoded as:
```
  identifier = date-time | sequence | serial | '%' | pkcs11-label
```
The date-time field is the date and time the key was created as reported by the HSM. The date-time is the concatenation of the hexadecimal representation of each of date-time component, i.e. 0x07E2 is 2018 and 0x07E2021A021533 is 2018-02-26 02:21:51.

The sequence field is a two byte value used to prevent identifier collisions for keys created at the same time. The sequence value is always 0 for the first key created at a specific time. Additional keys created at that same time will have a non-zero value derived from a global generator (i.e. the value is not associated with the time of creation).

The serial is the hexadecimal encoding of the HSM's serial number, i.e. K0701001 = 4B30373031303031.

The pkcs11-label is the first seven bytes of the user label, null-padded if required.

The key-policy defines attributes such as the allowed functions (e.g. sign, encrypt, export) and is further described as:
```
  key-policy = version | algorithm | flags
```
The version must be 0x0002. The algorithm is a two byte sequence having the following known values:
- 0x0001 = RSA
- 0x0016 = 3DES

The flags is a six byte sequence with the following values:

The second byte:
- 0b00000001 Encypher
- 0b00000010 Decypher
- 0b00000100 CanMacGen
- 0b00001000 CanMacVer
- 0b00010000 Sign
- 0b00100000 Verify Signature
- 0b01000000 Import
- 0b10000000 Export

The fifth byte:
- 0b00000001 DecryptKeys
- 0b00000010 EncryptKeys

The sixth byte:
- 0b00000100 Token

### PIN recovery
The User and SO PINs are stored in the keymap config file (keymap.config.db) using one SHA-1 hash round without a salt. The snippet below shows the relevant lines of a keymap config file with User and SO PINs of "1234" and "5678" respectively.
```
256,@UserAuthenicationToken@,@7110EDA4D09E062AA5E4A390B0A572AC0D2C0220@
256,@SOAuthenticationToken@,@2ABD55E001C524CB2CF6300A89CA6366848A77D5@
```

### Example code
keyper.py provides a function to derive the disk encryption key from a supplied PIN. When run as a main program, keyper.py uses the cryptography package to decrypt rows of a keymap file provided via stdin.

```bash
  python3 keyper.py [pin] < keymap.db
```