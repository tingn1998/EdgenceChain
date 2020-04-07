from ds.Transaction import Transaction
from ds.MerkleNode import MerkleNode
from ds.TxIn import TxIn
from ds.TxOut import TxOut
from ds.Block import Block
from consensus.Consensus import PoW
from params.Params import Params
from script import scriptBuild
from utils.Utils import Utils

import time


txns = [
    Transaction(
        txins=[TxIn(to_spend=None, signature_script=b"0", sequence=0)],
        txouts=[
            TxOut(
                value=5000000000,
                pk_script=scriptBuild.get_pk_script(
                    "1NY36FKZqM97oEobfCewhUpHsbzAUSifzo"
                ),
            )
        ],
        serviceId=None,
        postId=None,
        actionId=None,
        data=None,
        locktime=None,
    )
]
merkle_hash = MerkleNode.get_merkle_root_of_txns(txns)
print(f"merkle_hash={merkle_hash.val}")

genesis_block = Block(
    version="5465616d3a20456467656e63650a4c65616465723a20776f6c6662726f746865720a4d656d626572733a2063626f7a69"
    "2c204c6561684c69752c207069616f6c69616e676b622c2053616c7661746f7265303632362c2053696c7669614c69313"
    "232352c204a69617169204c69752c2078696179756e696c0a",
    prev_block_hash=None,
    merkle_hash=merkle_hash.val,
    timestamp=1554460209,
    bits=Params.INITIAL_DIFFICULTY_BITS,
    nonce=None,
    txns=txns,
)


def mine(block: Block) -> Block:
    """
    A minimal function for calculating genisis_block nonce.
    """

    start = time.time()
    nonce = 0
    target = 1 << (256 - block.bits)

    while int(Utils.sha256d(block.header(nonce)), 16) >= target:
        nonce += 1

    block = block._replace(nonce=nonce)
    duration = max(time.time() - start, 0.0001)
    khs = (block.nonce // duration) // 1_000
    print(
        f"genesis_block found at nonce={nonce} using {round(duration, 4)}s at rate {khs}KH/s"
    )
    print(f"blockid={block.id}")
    return block


genesis_block = mine(genesis_block)

# Sample output:
# $ python3 getgenesisblock.py
# a578b7a3bdc2d1385bce32a445a8ec4ffb9ab78b76afc30f53787b3189be289c
# genesis_block found at nonce=48747115 using 374.1626s at rate 130.0KH/s
# blockid=000000f4f713d04b1fb3265a0eb9e6f987ed6f4197597587ce409442534780d5
