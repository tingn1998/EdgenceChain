from wallet.Wallet import Wallet
from p2p.Peer import Peer
from p2p.Message import Message
from p2p.Message import Actions
from params import Params
from utils.Utils import Utils
from params.Params import Params

from ds.Transaction import Transaction
from ds.Block  import Block
from ds.BaseUTXO_Set import BaseUTXO_Set
from ds.BaseMemPool import BaseMemPool
from ds.BlockChain import BlockChain
from ds.TxIn import TxIn
from ds.TxOut import TxOut
from ds.MerkleNode import MerkleNode
from ds.UnspentTxOut import UnspentTxOut
from ds.OutPoint import OutPoint

import os
import time
import random
import socket
import threading
import logging
import argparse
import binascii


logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


class EdgeHand(object):

    def __init__(self, args):

        self.args = args
        self.gs = dict()
        self.gs['Block'], self.gs['Transaction'], self.gs['UnspentTxOut'], self.gs['Message'], self.gs['TxIn'], \
            self.gs['TxOut'], self.gs['Peer'], self.gs['OutPoint']= globals()['Block'], globals()['Transaction'], \
            globals()['UnspentTxOut'],globals()['Message'], globals()['TxIn'], globals()['TxOut'], globals()['Peer'], \
                                                                    globals()['OutPoint']

        self.chain_lock = threading.RLock()

        self.wallet = Wallet.init_wallet(args.wallet)
        self.peerList = Peer.init_peers(Params.PEERS_FILE)

    def getPort(self):
        if self.peerList:
            peer = random.sample(self.peerList, 1)[0]
        else:
            peer = Peer('127.0.0.1', 9999)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return peer, port

    def getRecv(self, peer, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', port))
        s.listen(True)
        conn, addr = s.accept()
        timeout = time.time() + 10
        message = None
        while True and time.time() < timeout:
            if addr[0] == peer[0]:
                message = Utils.read_all_from_socket(conn, self.gs)
                if message:
                    return message
            else:
                logger.exception(f'[EdgeHand] received from {addr} instead of {peer}')
        conn.close()
        return message

    def getBalance4Addr(self, wallet_addr):
        with self.chain_lock:
            peer, port = self.getPort()
            message = Message(Actions.Balance4Addr, wallet_addr, port)
            if Utils.send_to_peer(message, peer):
                logger.info(f'[EdgeHand] succeed to send Balance4Addr to {peer}')
                msg = self.getRecv(peer, port)
                if msg:
                    logger.info(f'[EdgeHand] received Balance4Addr from peer {peer}')
                    print(f'#{msg.data}# in address {wallet_addr}')
                    return msg.data
            else:
                logger.info(f'[EdgeHand] failed to send Balance4Addr to {peer}')

    def getUTXO4Addr(self, wallet_addr):
        with self.chain_lock:
            peer, port = self.getPort()
            message = Message(Actions.UTXO4Addr, wallet_addr, port)
            if Utils.send_to_peer(message, peer):
                logger.info(f'[EdgeHand] succeed to send UTXO4Addr to {peer}')
                msg = self.getRecv(peer, port)
                if msg:
                    logger.info(f'[EdgeHand] received UTXO4Addr from peer {peer}')
                    print(f'#{len(msg.data)}# utxo in address {wallet_addr}')
                    return msg.data
            else:
                logger.info(f'[EdgeHand] failed to send UTXO4Addr to {peer}')

    def sendTransaction(self, to_addr, value):
        selected = set()
        my_balance = list(sorted(self.getUTXO4Addr(self.wallet.my_address), key=lambda i: (i.value, i.height)))
        if sum(i.value for i in my_balance) <= value:
            logger.info(f'[EdgeHand] lack of balance.')
            return
        for coin in my_balance:
            selected.add(coin)
            if sum(i.value for i in selected) > value:
                break

        txout = TxOut(value=value, to_address=to_addr)
        txin = [self.makeTxin(coin.outpoint, txout) for coin in selected]
        txn = Transaction(txins=txin, txouts=[txout])
        logger.info(f'[EdgeHand] built txn {txn}')
        logger.info(f'[EdgeHand] broadcasting txn {txn.id}')
        with self.chain_lock:
            peer, port = self.getPort()
            message = Message(Actions.TxRev, txn, port)
            if Utils.send_to_peer(message, peer):
                logger.info(f'[EdgeHand] succeed to send TxRev to {peer}')
                msg = self.getRecv(peer, port)
                if msg:
                    logger.info(f'[EdgeHand] received TxConfirm True from {peer}')
                else:
                    logger.info(f'[EdgeHand] TxConfirm failed')
            else:
                logger.info(f'[EdgeHand] failed to send TxRev to {peer}')

    def getTxStatus(self, txid: str):
        with self.chain_lock:
            peer, port = self.getPort()
            message = Message(Actions.TxStatusReq, txid, port)
            if Utils.send_to_peer(message, peer):
                logger.info(f'[EdgeHand] succeed to send UTXO4Addr to {peer}')
                msg = self.getRecv(peer, port)
                if msg:
                    print(msg.data)
            else:
                logger.info(f'[EdgeHand] failed to send TxStatus to {peer}')

    def makeTxin(self, outpoint: OutPoint, txout: TxOut) -> TxIn:
        sequence = 0
        pk = self.wallet.signing_key.verifying_key.to_string()
        spend_msg = Utils.sha256d(
                    Utils.serialize(outpoint) + str(sequence) +
                    binascii.hexlify(pk).decode() + Utils.serialize([txout])).encode()
        return TxIn(to_spend=outpoint, unlock_pk=pk,
            unlock_sig=self.wallet.signing_key.sign(spend_msg), sequence=sequence)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='EdgeHand for EdgenceChain.')
    parser.add_argument('--wallet', required=False, default="mywallet.dat")
    parser.add_argument('--balance', required=False, default="")
    parser.add_argument('--txn', required=False, default="")
    parser.add_argument('--utxo', required=False, default="")
    parser.add_argument('--send', required=False, default="")
    parser.add_argument('--value', required=False, default=0)
    args = parser.parse_args()
    edgehand = EdgeHand(args)
    if args.balance:
        edgehand.getBalance4Addr(args.balance)
    if args.utxo:
        edgehand.getUTXO4Addr(args.utxo)
    if args.send and int(args.value):
        edgehand.sendTransaction(args.send, int(args.value))
    if args.txn:
        edgehand.getTxStatus(args.txn)