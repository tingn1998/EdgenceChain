import hashlib

__all__ = ['sha1', 'sha256', 'sha256d', 'ripemd160', 'hash160', 'decode_check', 'encode_check']


# ————————————————Hash Utils——————————————————
def sha1(data):
    return hashlib.sha1(data).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()


def hash160(data):
    return ripemd160(sha256(data))


# —————————————outAddress Check Utils————————————


# See: https://en.bitcoin.it/wiki/Technical_background_of_Bitcoin_addresses
def publickey_to_address(publickey, version=chr(0)):
    return pubkeyhash_to_address(hash160(publickey), version)


def pubkeyhash_to_address(publickey_hash, version=chr(0)) -> str:
    return encode_check(version + publickey_hash)


# Returns the base58 encoding with a 4-byte checksum.
def encode_check(payload):
    # 截取最后四位
    checksum = sha256d(payload)[:4]
    return b58encode(payload + checksum)


# Returns the base58 decoded value, verifying the checksum.
def decode_check(payload):
    payload = b58decode(payload, None)
    if payload and sha256d(payload[:-4])[:4] == payload[-4:]:
        return payload[:-4]
    return None


# ——————————————————base58 Utils————————————————————

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


# encode v, which is a string of bytes, to base58.
def b58encode(v):

    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)

    result = ''
    while long_value >= __b58base:
        (div, mod) = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


# decode v into a string of len bytes
def b58decode(v, length=None):

    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        (div, mod) = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result
