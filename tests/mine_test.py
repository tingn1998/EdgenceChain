from ds.Block import Block
from consensus.Consensus import PoW
import threading
import time

bits_list = [15, 21, 22, 23, 24, 25]
for bits in bits_list:
    time_start = time.time()
    for iter in range(10):
        genesis_block = Block.genesis_block()
        genesis_block = genesis_block._replace(bits = bits)
        genesis_block = genesis_block._replace(timestamp = time.time())
        genesis_block = PoW.mine(genesis_block, threading.Event())
        print(genesis_block.bits, genesis_block.nonce, genesis_block.id)
    time_sum = time.time() - time_start
    print(f'when bits is {bits}, average mining time is {time_sum/10}')
