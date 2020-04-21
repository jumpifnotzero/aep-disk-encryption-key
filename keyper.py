from collections import namedtuple
import csv
import datetime
import hashlib
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KeyPolicy = namedtuple('KeyPolicy', 'version algorithm flags')
Identifier = namedtuple('Identifier', 'date sequence serial label')


def keymap(stream, pin):
    """
    A generator that returns the label and decrypted data for each entry in a keymap file.
    Public key entries do not have encrypted data; instead None is returned.
    The decrypted data will be corrupt if the supplied pin is incorrect.
    :param Iterator stream: iterator that returns keymap.db entries
    :param bytes pin: the pin protecting the encrypted data
    :rtype: (str, bytes)
    """
    cipher = Cipher(algorithms.TripleDES(derive_dek(pin)), modes.CBC(bytes(8)), backend=default_backend())
    for row in csv.reader(stream, delimiter=',', quotechar='@'):

        label = row[10]
        identifier = None

        if len(row[2]) > 0:
            decryptor = cipher.decryptor()
            data = decryptor.update(bytes.fromhex(row[2])) + decryptor.finalize()

            unpadder = padding.PKCS7(64).unpadder()
            identifier = unpadder.update(data) + unpadder.finalize()

        yield label, identifier


def decode(data):
    """
    Decodes the decrypted data into its components.
    :param bytes data: the decrypted data to decode
    :rtype: (int, Identifier, KeyPolicy)
    :raises: Exception:
    """
    magic, _, key_size, date, serial, label, key_policy = struct.unpack('>IHI18s16sx7s12s', data)
    if magic != 0xFFFFFFFF:
        raise Exception("Invalid data")

    year, month, day, hour, minute, second, sequence = struct.unpack('>HBBBBBH', bytes.fromhex(date.decode()))
    date = datetime.datetime(year, month, day, hour, minute, second)
    version, algorithm, flags = struct.unpack('>HH8s', key_policy)
    return key_size, Identifier(date, sequence, bytes.fromhex(serial.decode()), label), KeyPolicy(version, algorithm, flags)


def derive_dek(pin):
    """
    Returns a 168-bit key derived from the given pin.
    The length of the return value is 192-bits; the 168-bit key with parity bits suitable for TripleDES.
    :param bytes pin: the pin
    :rtype: bytearray
    """
    return set_odd_parity(expand(hashlib.pbkdf2_hmac('SHA1', pin, salt(pin), 10, 0x15)))


def salt(pin):
    """
    Returns a salt given the supplied pin.
    :param bytes pin: the pin
    :rtype: bytes
    """
    m = hashlib.sha1()
    m.update(b'\x55\x55\x55\x55\x55\x55\x55\x55')
    m.update(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
    m.update(pin)
    m.update(b'\x55\x55\x55\x55\x55\x55\x55\x55')
    m.update(b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa')
    return m.digest()


def expand(buf):
    """
    Returns a new bytearray containing the contents of buf expanded with space for parity bit on each byte.
    The parity bit is not set and is always zero.
    :param bytes buf: 168-bit key
    :rtype: bytearray
    """
    out = bytearray(24)

    out[0] = buf[0] & 0xFE
    out[1] = (buf[0] & 0x01) << 7 | (buf[1] & 0xFC) >> 1
    out[2] = (buf[1] & 0x03) << 6 | (buf[2] & 0xF8) >> 2
    out[3] = (buf[2] & 0x07) << 5 | (buf[3] & 0xF0) >> 3
    out[4] = (buf[3] & 0x0F) << 4 | (buf[4] & 0xE0) >> 4
    out[5] = (buf[4] & 0x1F) << 3 | (buf[5] & 0xC0) >> 5
    out[6] = (buf[5] & 0x3F) << 2 | (buf[6] & 0x80) >> 6
    out[7] = (buf[6] & 0x7F) << 1

    out[8] = buf[7] & 0xFE
    out[9] = (buf[7] & 0x01) << 7 | (buf[8] & 0xFC) >> 1
    out[10] = (buf[8] & 0x03) << 6 | (buf[9] & 0xF8) >> 2
    out[11] = (buf[9] & 0x07) << 5 | (buf[10] & 0xF0) >> 3
    out[12] = (buf[10] & 0x0F) << 4 | (buf[11] & 0xE0) >> 4
    out[13] = (buf[11] & 0x1F) << 3 | (buf[12] & 0xC0) >> 5
    out[14] = (buf[12] & 0x3F) << 2 | (buf[13] & 0x80) >> 6
    out[15] = (buf[13] & 0x7F) << 1

    out[16] = buf[14] & 0xFE
    out[17] = (buf[14] & 0x01) << 7 | (buf[15] & 0xFC) >> 1
    out[18] = (buf[15] & 0x03) << 6 | (buf[16] & 0xF8) >> 2
    out[19] = (buf[16] & 0x07) << 5 | (buf[17] & 0xF0) >> 3
    out[20] = (buf[17] & 0x0F) << 4 | (buf[18] & 0xE0) >> 4
    out[21] = (buf[18] & 0x1F) << 3 | (buf[19] & 0xC0) >> 5
    out[22] = (buf[19] & 0x3F) << 2 | (buf[20] & 0x80) >> 6
    out[23] = (buf[20] & 0x7F) << 1

    return out


def set_odd_parity(buf):
    """
    Modifies the supplied bytearray to set odd parity on the last bit of each byte.
    This function requires the last (parity) bit is zero.
    :param bytearray buf: a 192-bit buffer containing a 168-bit key
    :rtype: bytearray
    """
    for i in range(0, len(buf)):
        v = buf[i]
        v ^= v >> 4
        v &= 0xf
        buf[i] |= (0x9669 >> v) & 1

    return buf


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]:s} pin")
        exit(1)

    pin = sys.argv[1].encode()

    for label, identifier in keymap(sys.stdin, pin):
        if identifier:
            print(f"{label:s} {decode(identifier)}")
