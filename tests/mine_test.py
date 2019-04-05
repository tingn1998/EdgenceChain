from ds.Block import Block
from consensus.Consensus import PoW
import threading
import time


time_start = time.time()

genesis_block = Block.genesis_block()
genesis_block = genesis_block._replace(bits = 24)
genesis_block = genesis_block._replace(timestamp = 1554460209)
genesis_block = PoW.mine(genesis_block, threading.Event())
print(genesis_block.bits, genesis_block.nonce, genesis_block.id)

