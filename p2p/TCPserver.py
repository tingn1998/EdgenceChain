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
from ds.OutPoint import OutPoint
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
from ds.MerkleNode import MerkleNode

from p2p.Message import Message
from p2p.Message import Actions
from persistence import Persistence

logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)



class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, ip_port, tcp_handler_class, active_chain: BlockChain, side_branches: Iterable[BlockChain], \
                 orphan_blocks: Iterable[Block], utxo_set: BaseUTXO_Set, mempool: BaseMemPool, peers: Iterable[Peer], \
                 mine_interrupt: threading.Event, ibd_done: threading.Event, chain_lock: _thread.RLock):


        self.active_chain = active_chain
        self.side_branches = side_branches
        self.orphan_blocks = orphan_blocks
        self.utxo_set = utxo_set
        self.mempool = mempool
        self.peers = peers
        self.mine_interrupt = mine_interrupt
        self.ibd_done = ibd_done
        self.chain_lock = chain_lock

        socketserver.TCPServer.__init__(self, ip_port, tcp_handler_class)
        logger.info(f'[p2p] listening on {Params.PORT_CURRENT}')

class TCPHandler(socketserver.BaseRequestHandler):


    def handle(self):

        # self.server is an instance of the ThreadedTCPServer
        self.active_chain = self.server.active_chain
        self.side_branches = self.server.side_branches
        self.orphan_blocks = self.server.orphan_blocks
        self.utxo_set = self.server.utxo_set
        self.mempool = self.server.mempool
        self.peers = self.server.peers
        self.mine_interrupt = self.server.mine_interrupt
        self.ibd_done = self.server.ibd_done
        self.chain_lock = self.server.chain_lock




        self.gs = dict()
        self.gs['Block'], self.gs['Transaction'], self.gs['UnspentTxOut'], self.gs['Message'], self.gs['TxIn'], self.gs['TxOut'], self.gs['Peer'], self.gs['OutPoint']= \
                    globals()['Block'], globals()['Transaction'], globals()['UnspentTxOut'], globals()['Message'], \
                    globals()['TxIn'], globals()['TxOut'], globals()['Peer'], globals()['OutPoint']
        try:
            #logger.info(f'type of self.request is {type(self.request)} before read')
            message = Utils.read_all_from_socket(self.request, self.gs)
            #logger.info(f'message is {message}')
            #logger.info(f'type of self.request is {type(self.request)} after read')
        except:
            logger.exception(f'[p2p] Invalid meassage from peer {self.request.getpeername()[0]}')
            return


        if not isinstance(message, Message):
            logger.info(f'[p2p] Not a Message from peer {self.request.getpeername()[0]}')
            return
        else:
            peer = Peer(str(self.request.getpeername()[0]), int(message.port))
            #if peer == Peer('127.0.0.1', Params.PORT_CURRENT) or \
            #    peer == Peer('localhost', Params.PORT_CURRENT) or \
            #        peer.ip == '0.0.0.0' or \
            #        peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
            #    logger.info(f'[p2p] new found {peer} is the current node itself, and does nothing for it')
            #    return




        action = int(message.action)
        if action == Actions.BlocksSyncReq:
            self.handleBlockSyncReq(message.data, peer)
        elif action == Actions.BlocksSyncGet:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()
            if message.srpeer is not None:
                peer = message.srpeer
            self.handleBlockSyncGet(message.data, peer)
        elif action == Actions.TxStatusReq:
            self.handleTxStatusReq(message.data, peer)
        elif action == Actions.UTXO4Addr:
            self.handleUTXO4Addr(message.data, peer)
        elif action == Actions.Balance4Addr:
            self.handleBalance4Addr(message.data, peer)
        elif action == Actions.TxRev:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()
            self.handleTxRev(message.data, peer)
        elif action == Actions.BlockRev:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()
            if message.srpeer is not None:
                peer = message.srpeer
            self.handleBlockRev(message.data, peer)
        elif action == Actions.PeerExtend:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()
            self.handlePeerExtendGet(message.data, peer)
        elif action == Actions.TopBlocksSyncReq:
            self.handleTopBlockSyncReq(message.data, peer)
        elif action == Actions.TopBlockReq:
            self.handleTopBlockReq(peer)
        else:
            logger.exception(f'[p2p] received unwanted action request ')




    def sendPeerExtend(self):
        if len(self.peers) > 0:
            for _peer in self.peers:
                if random.random() < 0.2:
                    continue
                peer_samples = random.sample(self.peers, min(5, len(self.peers)))
                logger.info(f"[p2p] sending {len(peer_samples)} peers to {_peer}")
                Utils.send_to_peer(Message(Actions.PeerExtend, peer_samples, Params.PORT_CURRENT), _peer)

    def handleBlockSyncReq(self, blockid: str, peer: Peer):

        logger.info(f"[p2p] receive BlockSyncReq from peer {peer}")


        #with self.chain_lock:
        height = Block.locate_block(blockid, self.active_chain)[1]
        if height is None:
            logger.info(f'[p2p] cannot find blockid {blockid}, and do nothing for this BlockSyncReq from peer {peer}')
            message = Message(Actions.BlockRev, self.active_chain.chain[-1], Params.PORT_CURRENT)
            self.request.sendall(Utils.encode_socket_data(message))

            return
        else:
            logger.info(f"[p2p] receive BlockSyncReq at height {height} from peer {peer}")
        blocks = self.active_chain.chain[height:(height + Params.CHUNK_SIZE)]

        logger.info(f"[p2p] sending {len(blocks)} blocks to {peer}")

        message = Message(Actions.BlocksSyncGet, blocks, Params.PORT_CURRENT)
        self.request.sendall(Utils.encode_socket_data(message))

        if (peer not in self.peers) and not (peer == Peer('127.0.0.1', Params.PORT_CURRENT) or \
                peer == Peer('localhost', Params.PORT_CURRENT) or \
                    peer.ip == '0.0.0.0' or \
                    peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT)):

            self.peers.append(peer)
            logger.info(f'[p2p] add peer {peer} into peer list')
            Peer.save_peers(self.peers)
            self.sendPeerExtend()


    def handleTopBlockSyncReq(self, topN: int, peer: Peer):
        #with self.chain_lock:
        logger.info(f"[p2p] to handle TopBlockSyncReq with length {topN} from peer {peer}")
        blocks = self.active_chain.chain[-topN:]

        message = Message(Actions.BlocksSyncGet, blocks, Params.PORT_CURRENT)
        ret = self.request.sendall(Utils.encode_socket_data(message))
        logger.info(f"[p2p] sent {len(blocks)} blocks in handleTopBlockSyncReq to {peer}")

        if ret is None:
            if peer not in self.peers:
                if peer== Peer('127.0.0.1', Params.PORT_CURRENT) or \
                                peer == Peer('localhost', Params.PORT_CURRENT) or \
                                    peer.ip == '0.0.0.0' or \
                                    peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                    return
                self.peers.append(peer)
                logger.info(f'[p2p] add peer {peer} into peer list')
                Peer.save_peers(self.peers)
                self.sendPeerExtend()

    def handleTopBlockReq(self, peer: Peer):
        logger.info(f"[p2p] to handle TopBlokReq from peer {peer}")
        block = self.active_chain.chain[-1]

        message = Message(Actions.BlockRev, block, Params.PORT_CURRENT)
        ret = self.request.sendall(Utils.encode_socket_data(message))
        logger.info(f"[p2p] sent top block in handleTopBlockReq to {peer}")

        if ret is None:
        #if self.request.sendall(Utils.encode_socket_data(message)) is None:
            if peer not in self.peers:
                if peer== Peer('127.0.0.1', Params.PORT_CURRENT) or \
                                peer == Peer('localhost', Params.PORT_CURRENT) or \
                                    peer.ip == '0.0.0.0' or \
                                    peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                    return
                self.peers.append(peer)
                logger.info(f'[p2p] add peer {peer} into peer list')
                Peer.save_peers(self.peers)
                self.sendPeerExtend()


    def handleBlockSyncGet(self, blocks: Iterable[Block], peer: Peer):
        if peer != Peer('127.0.0.1', Params.PORT_CURRENT):
            logger.info(f"[p2p] receive {len(blocks)} blocks for BlockSyncGet from {peer}")
        new_blocks = [block for block in blocks if not Block.locate_block(block.id, self.active_chain, self.side_branches)[0]]
        logger.info(f'[p2p] {len(new_blocks)} of {len(blocks)} blocks from {peer} is new')

        if not new_blocks:
            logger.info('[p2p] initial block download complete, prepare to mine')
            self.ibd_done.set()
            return
        else:
            self.ibd_done.clear()

        for idx in range(len(new_blocks)-1):
            block = new_blocks[idx]
            if MerkleNode.get_merkle_root_of_txns(block.txns).val != block.merkle_hash:
                logger.info(f'[p2p] check of block headers is a failure for not wrong merkle hash given')
                return
            elif block.id != new_blocks[idx+1].prev_block_hash:
                logger.info(f'[p2p] check of block headers is a failure for not consistent block hash: block.id is {block.id}, and prev_block hash is {new_blocks[idx+1].prev_block_hash}')
                return
            else:
                pass


        with self.chain_lock:
            chain_idx  = TCPHandler.check_block_place(new_blocks[0], self.active_chain, self.utxo_set, \
                                                          self.mempool, self.side_branches)
            if chain_idx is not None and chain_idx >= 1:
                # if is side branches, append the blocks (one block left) to the side branches directly
                logger.info(f'[p2p] just append {len(new_blocks)-1} blocks to side branch {chain_idx}, leaving one block to '
                f'be coped with method TCPHandler.do_connect_block_and_after')
                while len(new_blocks) >= 2:
                    self.side_branches[chain_idx-1].chain.append(new_blocks.pop(0))


            for block in new_blocks:

                if chain_idx is not None and chain_idx >= 0:
                    if not TCPHandler.do_connect_block_and_after(block, chain_idx, self.active_chain, self.side_branches, \
                                                    self.mempool, self.utxo_set, self.mine_interrupt, self.peers):
                        return
                elif chain_idx is not None and chain_idx <= -1:
                    logger.info(f'[p2p] orphan or wrong block {block.id}')
                    break
                else:
                    logger.info(f'[p2p] do nothing for block {block.id}')


            new_tip_id = self.active_chain.chain[-1].id
        logger.info(f'[p2p] current chain height {self.active_chain.height}, and continue initial block download ... ')

        message = Message(Actions.BlocksSyncReq, new_tip_id, Params.PORT_CURRENT)


        if peer not in self.peers:
            if peer== Peer('127.0.0.1', Params.PORT_CURRENT) or \
                            peer == Peer('localhost', Params.PORT_CURRENT) or \
                                peer.ip == '0.0.0.0' or \
                                peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                return
            self.peers.append(peer)
            logger.info(f'[p2p] add peer {peer} into peer list')
            Peer.save_peers(self.peers)
            self.sendPeerExtend()

        if peer == Peer('127.0.0.1', Params.PORT_CURRENT):
            if len(self.peers) > 0:
                peer = random.sample(self.peers,1)[0]
            else:
                return
        with socket.create_connection(peer(), timeout=25) as s:
            s.sendall(Utils.encode_socket_data(message))
            logger.info(f'[p2p] succeed to send BlocksSyncReq to {peer}')
            msg_len = int(binascii.hexlify(s.recv(4) or b'\x00'), 16)
            data = b''
            while msg_len > 0:
                tdat = s.recv(1024)
                data += tdat
                msg_len -= len(tdat)

        message = Utils.deserialize(data.decode(), self.gs) if data else None
        if message:
            logger.info(f'[p2p] received blocks from peer {peer}')
            message = Message(Actions.BlocksSyncGet, message.data, Params.PORT_CURRENT, peer)
            Utils.send_to_peer(message, Peer('127.0.0.1', Params.PORT_CURRENT), itself = True)
            #logger.info(f'[p2p] send BlocksSyncGet to itself')
        else:
            logger.info(f'[p2p] recv nothing from peer {peer}')



    def handleTxStatusReq(self, txid: str, peer: Peer):
        def _txn_iterator(chain):
            return (
                (txn, block, height)
                for height, block in enumerate(chain, 1) for txn in block.txns)
        #with self.chain_lock:
        if txid in self.mempool.mempool:
            status = 0 #f'txn {txid} found in_mempool'
            message = Message(Actions.TxStatusRev, status, Params.PORT_CURRENT)
            #print(message)
            self.request.sendall(Utils.encode_socket_data(message))
            return
        for tx, block, height in _txn_iterator(self.active_chain.chain):
            if tx.id == txid:
                status = 1 #f'txn {txid} is mined in block {block.id} at height {height}'
                message = Message(Actions.TxStatusRev, status, Params.PORT_CURRENT)
                self.request.sendall(Utils.encode_socket_data(message))
                return
        status = 2 #f'txn {txid}:not_found'
        message = Message(Actions.TxStatusRev, status, Params.PORT_CURRENT)

        self.request.sendall(Utils.encode_socket_data(message))

    def handleUTXO4Addr(self, addr: str, peer: Peer):
        #with self.chain_lock:
        utxos4addr = [u for u in self.utxo_set.utxoSet.values() if u.to_address == addr]

        message = Message(Actions.UTXO4AddrRev, utxos4addr, Params.PORT_CURRENT)

        self.request.sendall(Utils.encode_socket_data(message))

    def handleBalance4Addr(self, addr: str, peer: Peer):

        #with self.chain_lock:
        utxos4addr = [u for u in self.utxo_set.utxoSet.values() if u.to_address == addr]
        val = sum(utxo.value for utxo in utxos4addr)


        message = Message(Actions.Balance4AddrRev, val, Params.PORT_CURRENT)
        self.request.sendall(Utils.encode_socket_data(message))


    def handleTxRev(self, txn: Transaction, peer: Peer):
        if isinstance(txn, Transaction):
            logger.info(f"[p2p] received txn {txn.id} from peer {peer}")
            with self.chain_lock:
                if self.mempool.add_txn_to_mempool(txn, self.utxo_set):
                    if len(self.peers) > 0:
                        for _peer in random.sample(self.peers, min(len(self.peers),5)):
                            if _peer != peer:
                                Utils.send_to_peer(Message(Actions.TxRev, txn, Params.PORT_CURRENT), _peer)
                else:
                    logger.info(f"[p2p] received txn {txn.id}, but validate failed.")
        else:
            logger.info(f'[p2p] {txn} is not a Transaction object in handleTxRev')
            return


    def handleBlockRev(self, block: Block, peer: Peer):
        if isinstance(block, Block):
            if peer != Peer('127.0.0.1', Params.PORT_CURRENT):
                logger.info(f"[p2p] received block {block.id} from peer {peer}")
            with self.chain_lock:
                chain_idx  = TCPHandler.check_block_place(block, self.active_chain, self.utxo_set, self.mempool, \
                                                          self.side_branches)
                if chain_idx is not None and chain_idx >= 0:
                    if not TCPHandler.do_connect_block_and_after(block, chain_idx, self.active_chain, self.side_branches, \
                                                       self.mempool, self.utxo_set, self.mine_interrupt, self.peers):
                        return
                    self.sendPeerExtend()
            if chain_idx is not None and chain_idx >= 0:
                if len(self.peers) > 0:
                    for _peer in random.sample(self.peers, min(len(self.peers),5)):
                        if _peer != peer:
                            Utils.send_to_peer(Message(Actions.BlockRev, block, Params.PORT_CURRENT), _peer)
            elif chain_idx is None:
                logger.info(f'[p2p] already seen block {block.id}, and do nothing')
            elif chain_idx == -1:
                #case of orphan block
                message = Message(Actions.TopBlocksSyncReq, 50, Params.PORT_CURRENT)
                if peer == Peer('127.0.0.1', Params.PORT_CURRENT):
                    peer = random.sample(self.peers,1)[0]
                with socket.create_connection(peer(), timeout=25) as s:
                    s.sendall(Utils.encode_socket_data(message))
                    logger.info(f'[p2p] succeed to send TopBlocksSyncReq to {peer}')
                    msg_len = int(binascii.hexlify(s.recv(4) or b'\x00'), 16)
                    data = b''
                    while msg_len > 0:
                        tdat = s.recv(1024)
                        data += tdat
                        msg_len -= len(tdat)

                message = Utils.deserialize(data.decode(), self.gs) if data else None
                if message:
                    logger.info(f'[p2p] received blocks from peer {peer}')
                    message = Message(Actions.BlocksSyncGet, message.data, Params.PORT_CURRENT, peer)
                    Utils.send_to_peer(message, Peer('127.0.0.1', Params.PORT_CURRENT), itself = True)
                    #logger.info(f'[p2p] send BlocksSyncGet to itself')
                else:
                    logger.info(f'[p2p] recv nothing from peer {peer}')


        else:
            logger.info(f'[p2p] {block} is not a Block')

    @classmethod
    def printBlockchainIDs(cls, chain: BlockChain, inv: str = 'ID sequence of blockchain '):
        new_branch_id = ''
        for block in chain.chain:
            new_branch_id += block.id[-10:]+' ,'
        logger.info(f'{inv}: {new_branch_id}')

    @classmethod
    def do_connect_block_and_after(cls, block: Block, chain_idx, active_chain: BlockChain, side_branches: Iterable[BlockChain], \
                                mempool: BaseMemPool, utxo_set: BaseUTXO_Set, mine_interrupt: threading.Event, \
                                peers: Iterable[Peer]) -> bool:
        if int(chain_idx) == int(Params.ACTIVE_CHAIN_IDX):
            if block.block_subsidy_fees != Block.get_block_subsidy(active_chain) + block.calculate_fees(utxo_set):
                #logger.info(f'{block.block_subsidy_fees} != {Block.get_block_subsidy(active_chain)} + {block.calculate_fees(utxo_set)}')
                logger.info(f'[p2p] subsidy and fees of this block are not right, so discard this block and return.')
                #logger.info(f'after check subsid_fees, and give out a logger.exception')
                return False
            else:
                #logger.info(f'[p2p] subsidy and fees of this block are right.')
                pass
            connect_block_success = active_chain.connect_block(block, active_chain, \
                                                    side_branches, \
                                    mempool, utxo_set, mine_interrupt, peers)
        else:
            connect_block_success = side_branches[chain_idx-1].connect_block(block, \
                                             active_chain, side_branches, \
                                    mempool, utxo_set, mine_interrupt, peers)

        if connect_block_success is not False:
            if len(active_chain.chain) % 1 == 0 or len(active_chain.chain) <= 5:
                Persistence.save_to_disk(active_chain)

            if connect_block_success is not True: # -1, success and reorg
                logger.info(f'[p2p] a successful reorg is found, begin to deal with {len(side_branches)} side branches')

                for branch_chain in side_branches:
                    logger.info(f'[p2p] number of blocks before slim side branch: {len(branch_chain.chain)}')

                    TCPHandler.printBlockchainIDs(branch_chain, '[p2p] side branch removed from active chain ')

                    fork_height_from_end = 0
                    for block in branch_chain.chain[::-1]:
                        if not Block.locate_block(block.id, active_chain)[0]:
                            if not Block.locate_block(block.prev_block_hash, active_chain)[0]:
                                fork_height_from_end += 1
                            else:
                                break
                        else:
                            branch_chain.chain = []
                            logger.info(f'[p2p] the whole body of this branch chain is in active chain')
                            break
                    if fork_height_from_end >= branch_chain.height and branch_chain.height != 0:
                        branch_chain.chain = []
                        logger.info(f'[p2p] all blocks are orphans to the current active chain')

                    else:
                        for num_to_pop in range(1, branch_chain.height-fork_height_from_end):
                            branch_chain.chain.pop(0)
                    logger.info(f'[p2p] number of blocks after slim side branch: {len(branch_chain.chain)}')


            side_branches_to_discard = []
            for branch_chain in side_branches:
                fork_block, fork_height, _ = Block.locate_block(branch_chain.chain[0].prev_block_hash,
                                                        active_chain)
                branch_height_real = branch_chain.height + fork_height
                if active_chain.height - branch_height_real > Params.MAXIMUM_ALLOWABLE_HEIGHT_DIFF:
                    side_branches_to_discard.append(branch_chain)
            if len(side_branches_to_discard) > 0:
                logger.info(f'[p2p] delete {len(side_branches_to_discard)} of side branches')
                for branch_chain in side_branches_to_discard:
                    side_branches.remove(branch_chain)
            for index, branch_chain in enumerate(side_branches, 1):
                branch_chain.index = index
        else:
            logger.exception(f'[p2p] connect_block returned a False value')
        return True

    @classmethod
    def check_block_place(cls, block: Block, active_chain: BlockChain, utxo_set: BaseUTXO_Set, mempool: BaseMemPool, \
                          side_branches: Iterable[BlockChain]) -> int:
        if Block.locate_block(block.id, active_chain, side_branches)[0]:
            logger.debug(f'[p2p] ignore block that already be seen: {block.id}')
            return None # already seen block

        try:
            chain_idx = block.validate_block(active_chain, utxo_set, mempool, side_branches)
        except BlockValidationError as e:
            if e.to_orphan:
                logger.info(f"[p2p]  block {block.id} failed validation as an orphan block")
                return -1  # orphan block
            else:
                logger.exception(f'[p2p] block {block.id} failed validation due to internal error in this block')
                return -2  # Internal error in this block


        if chain_idx != Params.ACTIVE_CHAIN_IDX and len(side_branches) < chain_idx:
            logger.info(
                f'[p2p] creating a new side branch (idx {chain_idx}) '
                f'for block {block.id}')
            side_branches.append(BlockChain(idx = chain_idx, chain = []))

        return chain_idx

    def handlePeerExtendGet(self, peer_samples: Iterable[Peer], peer: Peer):
        logger.info(f"[p2p] received {len(peer_samples)} peers from peer {peer}")
        peer_samples.append(peer)
        for peer_sample in peer_samples:
            if not isinstance(peer_sample, Peer):
                continue

            if peer_sample == Peer('127.0.0.1', Params.PORT_CURRENT) or \
                peer_sample == Peer('localhost', Params.PORT_CURRENT) or \
                    peer_sample.ip == '0.0.0.0' or \
                    peer_sample == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                continue
            if peer_sample in self.peers:
                continue
            self.peers.append(peer_sample)
            logger.info(f'[p2p] add peer {peer_sample} into peer list')
            Peer.save_peers(self.peers)

