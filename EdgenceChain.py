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
from p2p.TCPserver import (ThreadedTCPServer, TCPHandler)


from consensus.Consensus import PoW




logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class EdgenceChain(object):


    def __init__(self):

        self.active_chain: BlockChain = BlockChain(idx=Params.ACTIVE_CHAIN_IDX, chain=[Block.genesis_block()])
        self.side_branches: Iterable[BlockChain] = []
        self.orphan_blocks: Iterable[Block] = []
        self.utxo_set: UTXO_Set = UTXO_Set()
        self.mempool: MemPool = MemPool()
        self.wallet: Wallet = Wallet.init_wallet(Params.WALLET_FILE)

        #self.peers: Iterable[Peer] = Peer.init_peers(Params.PEERS_FILE)
        self.peerManager: PeerManager = PeerManager(Peer.init_peers(Params.PEERS_FILE))

        self.mine_interrupt: threading.Event = threading.Event()
        self.ibd_done: threading.Event = threading.Event()
        self.chain_lock: _thread.RLock = threading.RLock()
        self.peers_lock: _thread.RLock = threading.RLock()


        self.gs = dict()
        self.gs['Block'], self.gs['Transaction'], self.gs['UnspentTxOut'], self.gs['Message'], self.gs['TxIn'], self.gs['TxOut'], self.gs['Peer'], self.gs['OutPoint']= \
                    globals()['Block'], globals()['Transaction'], globals()['UnspentTxOut'], globals()['Message'], \
                    globals()['TxIn'], globals()['TxOut'], globals()['Peer'], globals()['OutPoint']





    def assemble_and_solve_block(self, txns=None)->Block:
        """
        Construct a Block by pulling transactions from the mempool, then mine it.
        """
        with self.chain_lock:
            #chain_use_id = [str(number).split('.')[0] + '.' + str(number).split('.')[1][:5] for number in [random.random()]][0]
            #logger.info(f'####### into chain_lock: {chain_use_id} of assemble_and_solve_block')

            prev_block_hash = self.active_chain.chain[-1].id if self.active_chain.chain else None

            block = Block(
                version=0,
                prev_block_hash=prev_block_hash,
                merkle_hash='',
                timestamp=int(time.time()),
                bits= Block.get_next_work_required(prev_block_hash, self.active_chain, self.side_branches),
                nonce=0,
                txns=[None, *txns] if txns else [None],
            )

            if block.bits is None:
                #logger.info(f'####### out of chain_lock: {chain_use_id} of assemble_and_solve_block')
                return None

            if not block.txns[1:]:
                block = self.mempool.select_from_mempool(block, self.utxo_set)
                if len(block.txns[1:]) > 0:
                    logger.info(f'{len(block.txns[1:])} transactions selected from mempool to construct this block')

            fees = block.calculate_fees(self.utxo_set)
            my_address = self.wallet()[2]
            coinbase_txn = Transaction.create_coinbase(
                my_address,
                Block.get_block_subsidy(self.active_chain) + fees,
                self.active_chain.height)
            #logger.info(f'####### out of chain_lock: {chain_use_id} of assemble_and_solve_block')

        block.txns[0] = coinbase_txn
        block = block._replace(merkle_hash=MerkleNode.get_merkle_root_of_txns(block.txns).val)


        if len(Utils.serialize(block)) > Params.MAX_BLOCK_SERIALIZED_SIZE:
            raise ValueError('txns specified create a block too large')

        block = PoW.mine(block, self.mine_interrupt)

        return block



    def initial_block_download(self):
        self.ibd_done.clear()
        peers = self.peerManager.getPeers()
        if peers:
            logger.info(f'start initial block download from {len(peers)} peers')
            peer_sample = random.sample(peers, min(len(peers),6))

            message = Message(Actions.BlocksSyncReq, self.active_chain.chain[-1].id, Params.PORT_CURRENT)
            for peer in peer_sample:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #socket.create_connection(peer(), timeout=25) as s:
                        s.settimeout(70)
                        #logger.info(f'[EdgenceChain] begin to connect to {peer}')
                        s.connect(peer())
                        #logger.info(f'[EdgenceChain] succeed to create socket connection with {peer}, and begin to send data ...')
                        s.sendall(Utils.encode_socket_data(message))
                        #logger.info(f'[EdgenceChain] succeed to send BlocksSyncReq to {peer}')
                        msg_len = int(binascii.hexlify(s.recv(4) or b'\x00'), 16)
                        data = b''
                        while msg_len > 0:
                            tdat = s.recv(1024)
                            data += tdat
                            msg_len -= len(tdat)

                    s.close()
                    message = Utils.deserialize(data.decode(), self.gs) if data else None
                    if message:
                        logger.info(f'[EdgenceChain] received blocks in initial_block_download from peer {peer}')
                        message = Message(message.action, message.data, Params.PORT_CURRENT, peer)
                        ret = Utils.send_to_peer(message, Peer('127.0.0.1', Params.PORT_CURRENT), itself = True)

                        if ret != 0:
                            logger.info(f'cannot send data to itself, and its port is {Params.PORT_CURRENT}')


                        #logger.info(f'[EdgenceChain] send BlocksSyncGet to itself')
                    else:
                        logger.info(f'[EdgenceChain] recv nothing from peer {peer}')
                except Exception as e:
                    #logger.exception(f'Error: {repr(e)}, and remove dead peer {peer}')
                    if peer in peers:
                        try:
                            with self.peers_lock:
                                self.peerManager.addLog(peer, 1)
                        except:
                            pass

        else:
            logger.info(f'no peer nodes existed, ibd_done is set')
            self.ibd_done.set()



    def start(self):

        def start_worker(workers, worker):
            workers.append(threading.Thread(target=worker, daemon=True))
            workers[-1].start()

        def mine_forever():
            logger.info(f'thread for mining is started....')
            def broadcast_new_mined_block():
                peers = self.peerManager.getPeers()
                for _peer in peers:
                    ret = Utils.send_to_peer(Message(Actions.BlockRev, block, Params.PORT_CURRENT), _peer)
                    if ret == 1:
                        if _peer in peers:
                            with self.peers_lock:
                                #self.peerManager.remove(_peer)
                                self.peerManager.block(_peer)

                    elif ret != 0:
                        with self.peers_lock:
                            self.peerManager.addLog(_peer, 1)
                    else:
                        with self.peers_lock:
                            self.peerManager.addLog(_peer, 0)
            while True:

                try:
                    block = self.assemble_and_solve_block()

                    if block:

                        threading.Thread(target=broadcast_new_mined_block).start()
                        #ret_outside_chain = False
                        with self.chain_lock:
                            #chain_use_id = [str(number).split('.')[0] + '.' + str(number).split('.')[1][:5] for number in [random.random()]][0]
                            #logger.info(f'####### into chain_lock: {chain_use_id} of mine_forever')

                            chain_idx  = TCPHandler.check_block_place(block, self.active_chain, self.utxo_set, \
                                                                      self.mempool, self.side_branches)

                            ret_outside_lock = False
                            if chain_idx is not None and chain_idx >= 0:
                                ret_outside_lock = TCPHandler.do_connect_block_and_after(block, chain_idx, self.active_chain, \
                                                                      self.side_branches, self.mempool, \
                                                               self.utxo_set, self.mine_interrupt)
                            #logger.info(f'####### out of chain_lock: {chain_use_id} of mine_forever')
                        if ret_outside_lock is True:
                            if len(self.active_chain.chain) % Params.SAVE_PER_SIZE == 0 or len(self.active_chain.chain) <= 5:
                                Persistence.save_to_disk(self.active_chain)


                        if chain_idx is not None and chain_idx >= 0:
                            pass
                        elif chain_idx is None:
                            logger.info(f'mined already seen block {block.id}, just discard it and go')
                        elif chain_idx == -2:
                            logger.info(f"mined an orphan block {block.id}, just discard it and go")
                        elif chain_idx == -1:
                            logger.info(f'a mined block {block.id} but failed validation')
                        else:
                            logger.info(f'unwanted result of check block place')
                except:
                    pass

        def initiative_sync():
            logger.info(f'thread for request top block periodically....')
            def work_to_do():
                logger.info(f'begin to work in another new thread of initiative_sync')
                try:
                    with self.peers_lock:
                        self.peerManager.update()
                        peers = self.peerManager.getPeers()
                        Peer.save_peers(peers, Params.PEERS_FILE)
                except:
                    pass

                try:

                    time_now = time.time()
                    with self.chain_lock:
                        for block in self.orphan_blocks:
                            if time_now - block.timestamp > Params.MAXIMUM_ALLOWABLE_HEIGHT_DIFF*Params.TIME_BETWEEN_BLOCKS_IN_SECS_TARGET:
                                self.orphan_blocks.remove(block)
                except:
                    pass

                getpeers = self.peerManager.getPeers(2)
                if len(getpeers) > 0:
                    peer = random.sample(getpeers, 1)[0]
                    try:
                        message = Message(Actions.TopBlockReq, None, Params.PORT_CURRENT)

                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #socket.create_connection(peer(), timeout=25) as s:
                            #logger.info(f'[EdgenceChain] begin to connect to {peer}')
                            s.connect(peer())
                            #logger.info(f'[EdgenceChain] succeed to create socket connection with {peer}, and begin to send data ...')
                            s.sendall(Utils.encode_socket_data(message))
                            logger.info(f'[EdgenceChain] succeed to send TopBlockReq to {peer}')
                            msg_len = int(binascii.hexlify(s.recv(4) or b'\x00'), 16)
                            data = b''
                            while msg_len > 0:
                                tdat = s.recv(1024)
                                data += tdat
                                msg_len -= len(tdat)
                        s.close()
                        message = Utils.deserialize(data.decode(), self.gs) if data else None
                        if message:
                            logger.info(f'[EdgenceChain] received top block from peer {peer}')
                            message = Message(Actions.BlockRev, message.data, Params.PORT_CURRENT, peer)
                            ret = Utils.send_to_peer(message, Peer('127.0.0.1', Params.PORT_CURRENT), itself = True)
                            if ret != 0:
                                logger.info(f'cannot send data to itself, and its port is {Params.PORT_CURRENT}')
                            else:
                                #logger.info(f'[EdgenceChain] send BlockRev to itself')
                                pass
                        else:
                            logger.info(f'[EdgenceChain] recv nothing from peer {peer}')

                    except:
                        self.peerManager.addLog(peer, 1)
            while True:
                #logger.info(f'another cycle to request top block in initiative sync')
                threading.Thread(target = work_to_do).start()
                time.sleep(Params.TIME_BETWEEN_BLOCKS_IN_SECS_TARGET*0.3)




        # single thread mode, no need for thread lock
        Persistence.load_from_disk(self.active_chain, self.utxo_set)
        #TCPHandler.printBlockchainIDs(self.active_chain, '[EdgenceChain] active chain')

        workers = []
        server = ThreadedTCPServer(('0.0.0.0', Params.PORT_CURRENT), TCPHandler, self.active_chain, self.side_branches,\
                                   self.orphan_blocks, self.utxo_set, self.mempool, self.peerManager, self.mine_interrupt, \
                                              self.ibd_done, self.chain_lock, self.peers_lock)
        start_worker(workers, server.serve_forever)
        self.initial_block_download()

        old_height = self.active_chain.height-0.5
        new_height = old_height+0.5
        while new_height > old_height:
            old_height = new_height
            wait_times = 3
            while not self.ibd_done.is_set():
                time.sleep(10)
                wait_times -= 1
                if wait_times <= 0:
                    break
            new_height = self.active_chain.height
            logger.info(f'{int(new_height-old_height)} more blocks got this time, waiting for blocks syncing ...')
        self.ibd_done.set()


        start_worker(workers, mine_forever)
        start_worker(workers, initiative_sync)
        
        [w.join() for w in workers]



