import binascii
import hashlib
from math import log

import ecdsa
from base58 import b58encode_check, b58decode_check

import wallet

from script import script
from script import scriptBuild
from script import scriptUtils

# THIS TOOLS is written by ljq. Contact jqliu_bupt@163.com for signature checking problems


# ----------Build Functions-----------
def pubkey_to_address(pubkey: bytes) -> str:
    if 'ripemd160' not in hashlib.algorithms_available:
        raise RuntimeError('missing ripemd160 hash algorithm')

    sha = hashlib.sha256(pubkey).digest()
    ripe = hashlib.new('ripemd160', sha).digest()

    address = b58encode_check(b'\x00' + ripe)
    address = address if isinstance(address, str) else str(address, encoding="utf-8")
    return address


# ----------Test Functions------------

# Done (public_key -> public_key_hash -> address)
def test_encode_decode_addr():

    print("")
    print("---------------preparing to generate the address---------------")
    # private key for receiver(B)
    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    print("private key：", end="")
    print(signing_key)

    # public key for receiver(B)
    verifying_key = signing_key.get_verifying_key()

    print("public key： ", end="")
    print(verifying_key)
    print("public key bytes： ", end="")
    print(verifying_key.to_string())

    # address for receiver(B)
    my_address = pubkey_to_address(verifying_key.to_string())

    print("receiver(B)'s address： ", end="")
    print(my_address)
    print("---------------get the address successfully---------------")
    print("")
    print("---------------checking the public_key_hash---------------")
    # decode the address to get public key for sending to receiver(B)

    public_key_hash_de = b58decode_check(my_address)[1:]

    print(binascii.hexlify(public_key_hash_de))

    print("the public key hash for the public key (decode version)： ", end="")
    print(public_key_hash_de)

    # encode the public key to get public key hash belong to receiver(B)

    data = scriptUtils.hash160(verifying_key.to_string())

    public_key_hash_org = data

    print("the public key hash for the public key (original version)： ", end="")
    print(public_key_hash_org)

    # check whether the hash is EQUAL

    print("opcode.EQUAL result: ", end="")
    print(bool(public_key_hash_de == public_key_hash_org))
    print("----------------checking process finished---------------")

    return None


def test_token_tokenizer(publickey_hash):
    print("---------TEST----------")

    # print hash value:
    print("Input hash_value: ", end="")
    print(publickey_hash)

    # get the pk_script
    pk_script = scriptBuild.make_pk_script(publickey_hash)

    print("正向产生的哈希脚本: ", end="")
    print(pk_script)

    Tokens = script.Tokenizer(pk_script)

    print("逆向解读出的token脚本: ", end="")
    print(Tokens)

    # print("公钥正常的哈希值： ", end="")

    print("---------DONE----------")

    return None


def test_script_check_sig(signature, public_key, transaction, input_index):



    return None


if __name__ == '__main__':

    # --------- Token: test_encode_decode_addr ----------

    # test_encode_decode_addr()

    # --------- Token: test_token_Tokenizer ---------

    # public_hash = b'fe50b84730fc9d691998c38cbcc0702d19e53610'
    #
    # print("The type of the public_hash is Bytes: ", end="")
    # print(isinstance(public_hash, bytes))
    #
    # test_token_tokenizer(public_hash)

    # the final pk_script built with make_pk_script()
    pk_script = b'v\xa9(fe50b84730fc9d691998c38cbcc0702d19e53610\x88\xac'

    # ---------- Script: test_check_signature -----------

    # signature =
    #
    # public_key =
    #
    # test_script_check_sig(signature, public_key, transaction, input_index)







