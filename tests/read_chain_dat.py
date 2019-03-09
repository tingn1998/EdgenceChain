import binascii
import time
import json
import hashlib
import threading
import _thread
import logging
import socketserver
import socket
import random
import os
from functools import lru_cache, wraps
from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)
from ds.Transaction import Transaction
from ds.Block  import Block
from ds.UnspentTxOut import UnspentTxOut
from utils.Errors import BlockValidationError
from utils.Utils import Utils
from params.Params import Params

from p2p.Message import Message

from p2p.Peer import Peer
from ds.BaseUTXO_Set import BaseUTXO_Set
from ds.BaseMemPool import BaseMemPool
from ds.BlockChain import BlockChain
from ds.TxIn import TxIn
from ds.TxOut import TxOut


from p2p.Message import Message
from p2p.Message import Actions
from p2p.Peer import Peer
from p2p.TCPserver import (ThreadedTCPServer, TCPHandler)

logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


CHAIN_PATH='../'+Params.CHAIN_FILE
if not os.path.isfile(CHAIN_PATH):
    logger.info(f'[persistence] chain storage file does not exist')
else:
    pass
try:
    with open(CHAIN_PATH, "rb") as f:
        block_len = int(f.read(20))
        logger.info(f'[persistence] {block_len} is claimed at the head of chain file')
        msg_len = int(f.read(20))
        gs = dict()
        gs['Block'], gs['Transaction'], gs['TxIn'], gs['TxOut'] = globals()['Block'], globals()['Transaction'], \
                                                                  globals()['TxIn'], globals()['TxOut']

        new_blocks = Utils.deserialize(f.read(msg_len), gs)

        logger.info(f'[persistence] loading {len(new_blocks)} blocks successful')
except Exception:
    logger.exception(f'[persistence] failded in loading from chain storage file')

for block in new_blocks:
    print(block.id)
    block.merkle_hash
    block.prev_block_hash
    block.id



def check_blocks(blocks: Iterable[Block]) -> bool:
    for block in blocks[1:]:
        id = block.id
        merkle_hash = block.merkle_hash
        prev_block_hash = block.prev_block_hash
    pass
