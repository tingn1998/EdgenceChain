import binascii
import hashlib

from base58 import b58encode_check, b58decode_check
import ecdsa

from script import script
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

def check_redeem_script_check():
    print("---------TEST----------")

    # the signature is no related to the redeem script, just verify the HASH process
    sign_a = b'$\xf3"\x02\xb3\x0b\xbf\xd5_[O\n\xac\xa41<<w[\x18\x1d\xb8:\xfc\xf2\x881\xde\xbe\x9b\xb3@\xe15%\xf0zx\xf4\xa5\xf3\xee@\x0el\xa7\x16w\x90\xbf\xf0r\xf9\x02i\xde\xbc\xe8\xf3\x14ap\xa2k'
    sign_b = b'\x16T4e\xd9\xa45\xa9x\xf2\xb6\xf5\xdeDq\x15N\xa6\xdf\x83\xfbW\xb8\xe2;\r\\H$ \xba\xab\xe3>\xa1C&\x92\x8fj\x1d\x12c\x92}\xab\xd4y\xf4\xd4\xe9\x11\\\x16\x1cZ\x0f\t\xc1\xe9\xedE\xf5\xab'

    sig_list = [sign_a, sign_b]

    # print(len_a)

    redeem_script = b'5240a3f99c8ed4ee64610fd1f78cc9a9037184c6b2966c8517252ab51da7e31334aff9b0ea0a0808b7358054fe28d595d65b7cf1452b9b7388891e77864f16a6512f408c6b1aa13ce4cf9f6a569ae1298cdd9b61f229ee80873c5c851158f3a21b833578203d1ed2b94718e3ce77c85f28875a7c8ac62125c2334faa4bd069edbc7fed40f58d19c1a09330385a7602e5bd3110f557c9e60cfe152e8dec3ed7465b9f1cf2905d5812eb73671c499b76b0b355bbdad3ddc6ddb5a0713fc329e429ead1a14753ae'

    signature = scriptBuild.get_signature_script_without_hashtype(sig_list, redeem_script)

    decode_redeem_script = binascii.hexlify(b58decode_check('3F6RnxFya9dtCTnkbwdPobo4eGMppRuNcR')[1:])

    p2sh_script = scriptBuild.get_p2sh_script(decode_redeem_script)

    valid = script.Script(b'', b'').process(signature, p2sh_script, b'', 0)

    print("Get the verify result: ", end="")
    print(valid)

    print("---------DONE----------")


if __name__ == '__main__':

    # just 2-3 method
    # check_redeem_script()

    check_redeem_script_check()

