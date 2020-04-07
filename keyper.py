import hashlib


def derive_dek(pin):
    """
    Returns a 192-bit key derived from the given pin.
    The effective key is 168-bits, suitable for 3-DES (3 independent 56-bit keys).
    :param pin: bytes
    :return: bytearray
    """
    return set_odd_parity(expand(hashlib.pbkdf2_hmac('SHA1', pin, salt(pin), 10, 0x15)))


def salt(pin):
    """
    Returns a salt given a pin.
    :param pin: str
    :return: bytes
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
    Returns a bytearray containing the contents of buf expanded with a parity bit on each byte.
    The parity bit is not set and is always zero.
    :param buf: sequence of bytes
    :return: bytearray
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
    This function requires the last (parity) bit is set to zero.
    :param buf: bytearray
    :return: bytearray
    """
    for i in range(0, len(buf)):
        v = buf[i]
        v ^= v >> 4
        v &= 0xf
        buf[i] |= (0x9669 >> v) & 1

    return buf


if __name__ == '__main__':
    import sys
    import pyDes

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]:s} pin encrypted-hex-value")
        exit(1)

    key = derive_dek(sys.argv[1].encode())
    des = pyDes.triple_des(key, mode=pyDes.CBC, IV=bytes(8), padmode=pyDes.PAD_PKCS5)
    print(des.decrypt(bytes.fromhex(sys.argv[2])))
