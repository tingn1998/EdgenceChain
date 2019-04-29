import binascii
import hashlib

from base58 import b58encode_check
import ecdsa

from script import scriptBuild
from script.script import Tokenizer

from utils.Utils import Utils
from params.Params import Params


def pubkey_to_address(pubkey) -> str:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise RuntimeError('missing ripemd160 hash algorithm')

    def hash_pubkey(data):
        sha = hashlib.sha256(data).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        return ripe

    if isinstance(pubkey, bytes):
        address = b58encode_check(b'\x00' + hash_pubkey(pubkey))
    elif isinstance(pubkey, list):
        # make redeem script and return P2SH address
        redeem = scriptBuild.get_redeem_script(pubkey)
        address = b58encode_check(b'\x05' + hash_pubkey(redeem))
    else:
        return ''

    # print(str(b58encode_check(b'\x00' + ripe)).encode('utf-8'))
    # print(type(b58encode_check(b'\x00' + ripe)))
    address = address if isinstance(address, str) else str(address, encoding="utf-8")
    return address


def build_spend_message(to_spend, pk, sequence, txouts):

    spend_msg = Utils.sha256d(
        Utils.serialize(to_spend) + str(sequence) +
        binascii.hexlify(pk).decode() + Utils.serialize(txouts)).encode()

    return spend_msg


def check_redeem_script():

    signing_key = []
    for i in range(Params.P2SH_PUBLIC_KEY):
        signing_key.append(ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1))

    verifying_key = []
    for i in range(Params.P2SH_PUBLIC_KEY):
        verifying_key.append(signing_key[i].get_verifying_key().to_string())

    # print("Verify_keys: ", end="")
    # print(verifying_key)

    # print(type(verifying_key))

    redeem_script = scriptBuild.get_redeem_script(verifying_key)
    # print(type(redeem_script))

    print("Redeem script as bytes: ", end="")
    print(redeem_script)

    print("Tokenizer the Redeem_script:", end="")
    print(Tokenizer(redeem_script))

    print("print P2PKH address: ", end="")
    print(pubkey_to_address(verifying_key[0]))
    print("print P2SH address:  ", end="")
    print(pubkey_to_address(verifying_key))


if __name__ == '__main__':

    # just 2-3 method
    check_redeem_script()

