# AEP Disk Encryption Key
This project documents the algorithm used to derive the Disk Encryption Key that protects information in the AEP PKCS#11 local token store. The Disk Encryption Key (DEK) is a 168-bit symmetric key derived from the PIN. A modified PBKDF2 algorithm is used to produce the 168-bits needed for the key. Readers should be familiar with AEP HSMs and [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2).

## PIN
The User and SO PINs are stored in the &lt;token&gt;.config.db file. The machine file describes the location of this token file for a specific slot.

PINs are stored using one SHA-1 hash round without a salt. PIN recovery requires finding the correct character sequence that provides a matching hash. The example below shows the contents of the file with User and SO PINs of "1234" and "5678" respectively.
```
256,@UserAuthenicationToken@,@7110EDA4D09E062AA5E4A390B0A572AC0D2C0220@
256,@SOAuthenticationToken@,@2ABD55E001C524CB2CF6300A89CA6366848A77D5@
```

## Disk Encryption Key
The disk encryption key protects specific information stored in the &lt;token&gt;.db file. The data is encrypted using Triple DES with three separate 56-bit keys. These keys are derived from the PIN using a modified PBKDF2 algorithm to produce 168-bits of data (3x 56-bit).

The salt is the SHA-1 hash of the PIN, padded on both sides by a fixed 16-octet sequence:
```
  salt = sha1 ( 0x55 * 8 | 0xAA * 8 | pin | 0x55 * 8 | 0xAA * 8 )
```

This algorithm uses two passwords in the PBKDF2 f() function. Each password is a 64-octet, null-padded PIN, that is xor'ed (^) with fixed values.
```
  password1 = ( pin | 0x00 * ( 64 - length ( pin ) ) ) ^ 0x36 * 64
  password2 = ( pin | 0x00 * ( 64 - length ( pin ) ) ) ^ 0x5C * 64
```

For every iteration in f(), the output is two chained hash functions using each of the two passwords. As with PBKDF2, the output of the f() function is the xor (^) of each iteration. The f() function is implemented as:
```
  f(passwords, salt, iterations, i)
    iteration1 = sha1 ( password2 | sha1 ( password1 | salt | i ) )
    iteration2 = sha1 ( password2 | sha1 ( password1 | iteration1 ) )
    ...
    iterationx = sha1 ( password2 | sha1 ( password1 | iterationx-1 ) )

    return iteration1 ^ iteration2 ... ^ iterationx
```

SHA-1 produces a 160-bit output, short of the 168-bits required for the key. As with PBKDF2, the f() function above is run again with i=2, concatenated with the first output, and truncated to 168-bits.
```
  c = 10
  dkLen = 21 (octets)

  output = f ( passwords, salt, c, 1 ) || f ( passwords, salt, c, 2 )
  key = truncate ( output, dkLen )
```

Parity bits are added to the 168-bit key to produce a 192-bit result. Triple-DES uses the least-significant bit for odd-parity. The following disk encryption key was derived from the PIN "1234".
```
E057CEF445571C38B07A4CABF7E97C169B70CD58A761AEBC
```

## Token store
Given the disk encryption key we can look into the data in the token store. The token store contains entries for each of the keys stored on the HSM. The file follows a CSV-format, without a header row, and with character-string values enclosed by '@'. Of the 49 columns, the data includes:
- Label (Column 11) and its value in hexadecimal (Column 12).
- Modulus in hexadecimal (Column 35)
- Exponent in hexadecimal (Column 36)
- Encrypted data in hexadecimal (Column 3)

Decrypting the value in Column 3 gives a character-string that has the following format:
```
  column-3 = magic-number | ???? | key-size | identifier | key-policy
```
The magic number is 0xffffffff. Question marks represent octets of unknown significance. The identifier is a value transmitted over-the-wire to the HSM when using this key. The identifier is further described as:
```
  identifier = date-time | sequence | serial | % | pkcs11-label
```
The date-time field is the time the key was created as measured by the HSM. The date-time is the hexadecimal representation of the decimal value of each component, i.e. 2018-02-26 02:21:51 = 0x07E2021A 021533. The 2-octet sequence field prevents identifier collisions. The serial is the hexadecimal encoding of the HSM's serial number, i.e. K0701001 = 4B30373031303031. The pkcs11-label is the first seven octets of the label, or a label null-padded to seven octets.

## Example code
A java-based implementation of the algorithm is included in this repository. The following two commands will compile and run it:
```
  javac DeriveDEK.java
  java DeriveDEK <pin>
```
OpenSSL can decrypt the data in the token store given the above key. The following decrypts the first row of a specified token store.
```
  cat <token>.db | head -n 1 | cut -f3 -d',' | tr -d '@' | xxd -r -p \
  | openssl enc -d -des-ede3-cbc -K <key> -iv 0000000000000000
```
## Further work
It may be possible to recover a token-store entry for secret keys stored on the HSM. The HSM's backup to USB feature includes the plain-text identifier, the previous missing link in constructing a plausable token-store entry. The public-component of a key-pair may not be recoverable.

## Notes
The library creates what appears to be a session key. This key is generated using a similar process to that above with the following inputs:
```
  random = PRNG 16 bytes.

  salt = sha1 ( password2 | sha1 ( password1 | random ) )

  password1 = ( random | 0x0 * ( 64 - length ( random ) ) ) ^ 0x36
  password2 = ( random | 0x0 * ( 64 - length ( random ) ) ) ^ 0x5C

  iterations = 250
```
