from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)
from ds.Block import Block
from ds.Transaction import Transaction
from ds.UnspentTxOut import UnspentTxOut
from ds.OutPoint import OutPoint
from p2p.Peer import Peer

from enum import Enum, unique



class Actions:
    BlocksSyncReq = 0
    BlocksSyncGet = 1
    TxStatusReq  = 2
    UTXO4Addr    = 3
    Balance4Addr = 4
    TxRev        = 5
    BlockRev     = 6
    TxStatusRev = 7
    UTXO4AddrRev = 8
    Balance4AddrRev = 9
    PeerExtend = 10
    TopBlocksSyncReq = 11
    TopBlockReq  = 12
    num2name = {'0':'BlocksSyncReq',
                   '1':'BlocksSyncGet',
                   '2':'TxStatusReq',
                   '3':'UTXO4Addr',
                   '4':'Balance4Addr',
                   '5':'TxRev',
                   '6':'BlockRev',
                   '7':'TxStatusRev',
                   '8':'UTXO4AddrRev',
                   '9':'Balance4AddrRev',
                   '10':'PeerExtend',
                   '11':'TopBlocksSyncReq',
                   '12':'TopBlockReq'}


class Message(NamedTuple):
    action: int
    data: Union[str, Iterable[Block], Iterable[UnspentTxOut], int, Transaction, Block, Iterable[Peer], OutPoint, bool]
    port: Union[None, int] = None
    srpeer: Peer = None





