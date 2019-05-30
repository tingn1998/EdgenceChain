import binascii
import hashlib
from math import log

import ecdsa
from base58 import b58encode_check, b58decode_check

from ds import MerkleNode


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

    public_key_hash_org = scriptUtils.hash160(verifying_key.to_string())

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

    print("Tokens 的操作码为：", end="")
    print(hex(Tokens[2]))
    print("当opcode==0x1ff时，其hash值为（bytes）类型", end="")
    print(Tokens.get_value(2))
    print(type(Tokens.get_value(2)))

    print("检验hash值与解码输出是否相等：", end="")
    print(bool(publickey_hash==Tokens.get_value(2)))

    # print("公钥正常的哈希值： ", end="")

    print("---------DONE----------")

    return None

def test_token_sig_tokenizer():

    print("---------TEST----------")

    # 产生签名脚本
    signature = b'a200548f8a634812284ad548e908feafe713b290215ed0273a5f28de622e40cb'

    signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    pk = signing_key.get_verifying_key()

    my_address = pubkey_to_address(pk.to_string())
    print("receiver(B)'s address： ", end="")
    print(my_address)

    pk_script = scriptBuild.get_pk_script(my_address)

    # 产生hash值以供验证
    public_key_hash_de = b58decode_check(my_address)[1:]
    print("解码得到的hash值为（二进制）： ", end="")
    print(binascii.hexlify(public_key_hash_de))

    print(type(pk.to_string()))

    signature_script = scriptBuild.get_signature_script_without_hashtype(signature, pk.to_string())

    tokens = script.Tokenizer(signature_script)

    print("签名脚本进入tokens：", end="")
    print(tokens)

    print("获取签名脚本中公钥部分：", end="")
    print(tokens.get_value(1))
    print("公钥hash值： ", end="")
    print(hex(tokens[1]))

    print("获取公钥对应的hash值：", end="")
    pk_hash = scriptUtils.hash160(tokens.get_value(1))
    print(pk_hash)
    print("二进制：", end="")
    print(binascii.hexlify(pk_hash))

    print("判断相等：", end="")
    print(bool(public_key_hash_de == pk_hash))

    print("---------TEST Script----------")

    print("检验栈操作是否可运行，注释check_signature部分：")

    print(script.Script.process(signature_script, pk_script, b'0', 1))

    print("---------DONE----------")

    # ---------TEST - ---------
    # receiver(B)
    # 's address： 1QJdAcCpy9ckG4tnDBq2EJmLBGsLGB2ZQ8
    # 解码得到的hash值为（二进制）： b'ffa02768058ca2305f449f2da4619e71a08b5db0'
    # <class 'bytes'>
    #
    # 签名脚本进入tokens：5090570079643391295836653930619568056975108647454484232055555845918370907568237548385703324612871250494025243147705324820182025617872473178512831315731298
    # 12437925785449238801746067915282852552951852862076944773142389933553787641793819115456526667601775483989502627061209560045577172510877154717230929234166842
    # 获取签名脚本中公钥部分：b'\xed{P\x98\xab\x9em\xee\xd2\x9a+P\xbey\xe2G)m\xbc@:@\x1eO\xfd\x9f\x82\x01c\xc5O\xfb\xa79A\xf8Z\x9d|\xeb\xd8\x1f\x95\xc4a\x18\xc6\xad\xebi)\x95\xb1v\x86\xf0\xcc\x04\xc28!5\x04:'
    # 公钥hash值： 0x1ff
    # 获取公钥对应的hash值：b"\xff\xa0'h\x05\x8c\xa20_D\x9f-\xa4a\x9eq\xa0\x8b]\xb0"
    # 二进制：b'ffa02768058ca2305f449f2da4619e71a08b5db0'
    # 判断相等：True
    # ---------TEST Script - ---------
    # 检验栈操作是否可运行，注释check_signature部分：
    # ok
    # True
    # ---------DONE - ---------

    return None


def test_encode_method1(pk_script):
    print("----------test encode 1----------")

    data = binascii.hexlify(pk_script)

    mid = bytes.decode(data)

    print(type(mid), end="")
    print(mid)

    re = str.encode(mid)

    print(type(re), end="")
    print(re)

    result = binascii.unhexlify(re)

    print(type(result), end="")

    print(result)

    print(bool(pk_script == result))

    print("----------done encode 1----------")

    return None


def test_encode_method2(pk_script):
    print("----------test encode 2----------")

    data = str(pk_script)

    print(data)

    re = data[2:-1]

    print(re)

    re_data = bytes.fromhex(re)

    print(re_data)

    print(type(re_data))

    print("----------done encode 2----------")

    return None


def test_merkle_build(txns):
    return MerkleNode.MerkleNode.get_merkle_root_of_txns(txns).val


def test_script_check_sig(signature, public_key, transaction, input_index):
    return None


if __name__ == '__main__':

    my_address = '1QAJPVXf6sLMeTRoqCuyjmZYNShFrwFFQ4'

    pk_script = b'v\xa9(ec394803acaf0ad750aa37b8ce147ff018d83a0d\x88\xac'
    print(scriptBuild.get_address_from_pk_script(pk_script))
    #
    # public_key_hash_de = b58decode_check(my_address)[1:]
    #
    # print(print(binascii.hexlify(public_key_hash_de)))

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

    # test_token_sig_tokenizer()

    # to_address = b'v\xa9(fe0d26ba472c5fe910ecff4f6b4fe24b67f7575f\x88\xac'

    # print(scriptBuild.get_address_from_pk_script(to_address))

    # --------- Encode: test_encode_method ----------

    # pk_script = b'v\xa9(fe50b84730fc9d691998c38cbcc0702d19e53610\x88\xac'

    # test_encode_method1(pk_script)

    # test_encode_method2(pk_script)

    # ---------- Merkle: test_merkle_build ----------

    # txns = [Transaction.Transaction(
    #     txins=[TxIn.TxIn(
    #         to_spend=None, signature_script=b'0', sequence=0)],
    #     txouts=[TxOut.TxOut(
    #         value=5000000000, pk_script=scriptBuild.get_pk_script('1NY36FKZqM97oEobfCewhUpHsbzAUSifzo')
    #     )],
    #     locktime=None)]
    #
    # merkle_hash = test_merkle_build(txns)
    #
    # print(merkle_hash)

    # ---------- Script: test_check_signature -----------

    #       {"_type": "Block",
    #       "bits": 22,
    #       "merkle_hash": "8cfb8d2d2ed9343461b0eefb73c775b9366a32e05e81b0e8946620e2f1935507",
    #       "nonce": 9051321,
    #       "prev_block_hash": null,
    #       "timestamp": 1547747173,
    #       "txns": [
    #       {"_type": "Transaction",
    #        "locktime": null,
    #       "txins": [{
    #           "_type": "TxIn",
    #           "sequence": 0,
    #           "to_spend": null,
    #           "unlock_pk": null,
    #           "unlock_sig": "30"}],
    #       "txouts": [{
    #           "_type": "TxOut",
    #           "to_address": "0000000000000000000000000000000000",
    #           "value": 5000000000}]}],
    #       "version": "5465616d3---179756e696c0a"}

    # public_key =
    #
    # test_script_check_sig(signature, public_key, transaction, input_index)
