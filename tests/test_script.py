import hashlib

import ecdsa
from base58 import b58encode_check

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

def test_token_get_addr():

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
    print("get the address successfully.")

    # decode the address to get public key for sending to receiver(B)

    # public_key = scriptUtils.hash160(my_address)
    #
    # print("decode the address to get the public key： ", end="")
    # print(public_key)

    # encode the public key to get public key hash belong to receiver(B)

    public_key_hash_org = scriptUtils.hash160(verifying_key.to_string())

    print("the public key hash for the public key (original version)： ", end="")
    print(public_key_hash_org)

    # public_key_hash = decode(my_address)
    #
    # print("the public key hash for the public key (decode version)： ", end="")
    # print(public_key_hash)

    return None


def test_token_Toknizer(publickey_hash):

    print("---------TEST----------")

    # print hash value:
    print("Input hash_value: ", end="")
    print(publickey_hash)

    # get the pk_script
    pk_script = scriptBuild.get_pk_script(publickey_hash)

    print("正向产生的哈希类型: ", end="")
    print(pk_script)

    Tokens = script.Tokenizer(pk_script)

    print("逆向解读出的token脚本: ", end="")
    print(Tokens)

    print("公钥正常的哈希值： ", end="")

    print("---------DONE----------")

    return None


if __name__ == '__main__':

    # --------- Token: test_token_Tokenizer ---------

    # public_hash = b'f256f3f62388e17b66e881f80b17a69dfc55b7e4'
    # public_hash2 = scriptBuild.Script('f256f3f62388e17b66e881f80b17a69dfc55b7e4').parse()
    #
    # test_token_Toknizer(public_hash)
    # test_token_Toknizer(public_hash2)

    # --------- Token: test_token_get_addr ----------

    test_token_get_addr()
