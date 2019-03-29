import hashlib

__all__ = ['sha1', 'sha256', 'sha256d', 'ripemd160', 'hash160']


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
