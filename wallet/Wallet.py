import hashlib
import logging
import os
from functools import lru_cache
import ecdsa
from base58 import b58encode_check

from script import scriptBuild

from params.Params import Params

logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class Wallet(object):

    def __init__(self, signing_key, verifying_key, my_address):
        self.signing_key = signing_key
        self.verifying_key = verifying_key
        self.my_address = my_address

    def __call__(self):
        return self.signing_key, self.verifying_key, self.my_address

    @classmethod
    def pubkey_to_address(cls, pubkey) -> str:
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
            logger.exception(f"[wallet] get the wrong pubkey in generating address")
            return ''

        # print(str(b58encode_check(b'\x00' + ripe)).encode('utf-8'))
        # print(type(b58encode_check(b'\x00' + ripe)))
        address = address if isinstance(address, str) else str(address, encoding="utf-8")
        return address


    @classmethod
    @lru_cache()
    def init_wallet(cls, path='wallet.dat'):
        if Params.SCRIPT_TYPE == 0:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    signing_key = ecdsa.SigningKey.from_string(
                        f.read(), curve=ecdsa.SECP256k1)
            else:
                logger.info(f"[wallet] generating new wallet: '{path}'")
                signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
                with open(path, 'wb') as f:
                    f.write(signing_key.to_string())

            verifying_key = signing_key.get_verifying_key()
            my_address = Wallet.pubkey_to_address(verifying_key.to_string())
            logger.info(f"[wallet] your address is {my_address}")

            return cls(signing_key, verifying_key, my_address)

        elif Params.SCRIPT_TYPE == 1:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    # get the list of private key
                    signing_key = [ecdsa.SigningKey.from_string(
                            f.read(), curve=ecdsa.SECP256k1) for i in range(Params.P2SH_PUBLIC_KEY)]
            else:
                logger.info(f"[wallet] generating new wallet: '{path}'")
                signing_key = [ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
                               for i in range(Params.P2SH_PUBLIC_KEY)]
                with open(path, 'wb') as f:
                    for i in range(Params.P2SH_PUBLIC_KEY):
                        f.write(signing_key[i].to_string())

            verifying_key = [signing_key[i].get_verifying_key().to_string()
                             for i in range(Params.P2SH_PUBLIC_KEY)]

            my_address = Wallet.pubkey_to_address(verifying_key)
            logger.info(f"[wallet] your address is {my_address}")

            return cls(signing_key, verifying_key, my_address)

