import binascii
import time
import copy
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
    Iterable,
    NamedTuple,
    Dict,
    Mapping,
    Union,
    get_type_hints,
    Tuple,
    Callable,
)


from utils.Errors import BlockValidationError
from utils.Utils import Utils

from params.Params import Params

from ds.OutPoint import OutPoint
from ds.UnspentTxOut import UnspentTxOut
from ds.TxIn import TxIn
from ds.TxOut import TxOut
from ds.Transaction import Transaction
from ds.Block import Block
from ds.UTXO_Set import UTXO_Set
from ds.MemPool import MemPool
from ds.MerkleNode import MerkleNode
from ds.BlockChain import BlockChain

from persistence import Persistence

from wallet.Wallet import Wallet

from p2p.Message import Message
from p2p.Message import Actions
from p2p.Peer import Peer
from p2p.PeerManager import PeerManager
from p2p.TCPserver import ThreadedTCPServer, TCPHandler


from consensus.Consensus import PoW


logging.basicConfig(
    level=getattr(logging, os.environ.get("TC_LOG_LEVEL", "INFO")),
    format="[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


class ListeningServer(object):
    """
    A pure listening server built for edgence explorer and
    edgence Android client to get information form blockchain,
    which avoids CPU usage for mining blocks.
    """

    def __init__(self):
        self.active_chain: BlockChain = BlockChain(
            idx=Params.ACTIVE_CHAIN_IDX, chain=[Block.genesis_block()]
        )
        self.side_branches: Iterable[BlockChain] = []
        self.orphan_blocks: Iterable[Block] = []
        self.utxo_set: UTXO_Set = UTXO_Set()
        self.mempool: MemPool = MemPool()
        self.wallet: Wallet = Wallet.init_wallet(Params.WALLET_FILE)

        # self.peers: Iterable[Peer] = Peer.init_peers(Params.PEERS_FILE)
        self.peerManager: PeerManager = PeerManager(Peer.init_peers(Params.PEERS_FILE))

        self.chain_lock: _thread.RLock = threading.RLock()
        self.peers_lock: _thread.RLock = threading.RLock()
        self.mine_interrupt: threading.Event = threading.Event()
        self.ibd_done: threading.Event = threading.Event()

        self.gs = dict()
        (
            self.gs["Block"],
            self.gs["Transaction"],
            self.gs["UnspentTxOut"],
            self.gs["Message"],
            self.gs["TxIn"],
            self.gs["TxOut"],
            self.gs["Peer"],
            self.gs["OutPoint"],
        ) = (
            globals()["Block"],
            globals()["Transaction"],
            globals()["UnspentTxOut"],
            globals()["Message"],
            globals()["TxIn"],
            globals()["TxOut"],
            globals()["Peer"],
            globals()["OutPoint"],
        )

    def start(self):
        Persistence.load_from_disk(self.active_chain, self.utxo_set)

        server = ThreadedTCPServer(
            ("0.0.0.0", Params.PORT_CURRENT),
            TCPHandler,
            self.active_chain,
            self.side_branches,
            self.orphan_blocks,
            self.utxo_set,
            self.mempool,
            self.peerManager,
            self.mine_interrupt,
            self.ibd_done,
            self.chain_lock,
            self.peers_lock,
        )

        self.ibd_done.set()

        server.serve_forever()

if __name__ == "__main__":
    listeningServer = ListeningServer()
    listeningServer.start()
