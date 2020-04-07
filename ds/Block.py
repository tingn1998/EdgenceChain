import binascii
import time
import json
import hashlib
import threading
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


from ds.UnspentTxOut import UnspentTxOut
from ds.OutPoint import OutPoint
from ds.Transaction import Transaction
from ds.BaseUTXO_Set import BaseUTXO_Set
from ds.BaseMemPool import BaseMemPool

from utils.Errors import BlockValidationError
from utils.Errors import TxnValidationError

from utils.Utils import Utils
from params.Params import Params
from ds.MerkleNode import MerkleNode
from ds.TxIn import TxIn
from ds.TxOut import TxOut
from params.Params import Params
import _thread
from ds.BaseBlockChain import BaseBlockChain

from script import scriptBuild

import ecdsa
from base58 import b58encode_check


logging.basicConfig(
    level=getattr(logging, os.environ.get("TC_LOG_LEVEL", "INFO")),
    format="[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


class Block(NamedTuple):

    version: int
    prev_block_hash: str
    merkle_hash: str
    timestamp: int
    bits: int
    nonce: int
    txns: Iterable[Transaction]

    def header(self, nonce=None) -> str:
        return (
            f"{self.version}{self.prev_block_hash}{self.merkle_hash}"
            f"{self.timestamp}{self.bits}{nonce or self.nonce}"
        )

    @property
    def id(self) -> str:
        return Utils.sha256d(self.header())

    @property
    def block_subsidy_fees(self):
        coinbase_txn: Transaction = self.txns[0]
        subsidy_fees = sum(txout.value for txout in coinbase_txn.txouts)
        return subsidy_fees

    @classmethod
    def genesis_block(cls):
        return cls(
            version="5465616d3a20456467656e63650a4c65616465723a20776f6c6662726f746865720a4d656d626572733a2063626f7a69"
            "2c204c6561684c69752c207069616f6c69616e676b622c2053616c7661746f7265303632362c2053696c7669614c69313"
            "232352c204a69617169204c69752c2078696179756e696c0a",
            prev_block_hash=None,
            merkle_hash="a578b7a3bdc2d1385bce32a445a8ec4ffb9ab78b76afc30f53787b3189be289c",
            timestamp=1554460209,
            bits=Params.INITIAL_DIFFICULTY_BITS,
            nonce=41912381,
            txns=[
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
                    locktime=None,
                    serviceId=None,
                    postId=None,
                    actionId=None,
                    data=None,
                )
            ],
        )

    @classmethod
    def get_block_subsidy(cls, active_chain: BaseBlockChain) -> int:
        """
        After specific number of blocks, subsidy of mining a block will be halved.
        """

        halvings = active_chain.height // Params.HALVE_SUBSIDY_AFTER_BLOCKS_NUM

        if halvings >= 64:
            return 0

        return 50 * Params.LET_PER_COIN // (2 ** halvings)

    @classmethod
    def locate_block(
        cls,
        block_hash: str,
        active_chain: BaseBlockChain,
        side_branches: Iterable[BaseBlockChain] = None,
    ):
        """
        Using block_hash to get a tuple (block, height, chain_idx)
        """

        chains = (
            [active_chain] if side_branches is None else [active_chain, *side_branches]
        )
        for chain_idx, blockchain in enumerate(chains):
            for height, block in enumerate(blockchain.chain, 1):
                if block.id == block_hash:
                    if chain_idx != Params.ACTIVE_CHAIN_IDX:
                        fork_height = Block.locate_block(
                            blockchain.chain[0].prev_block_hash, active_chain
                        )[1]
                        height = fork_height + height
                    return (block, height, chain_idx)
        return (None, None, None)

    @classmethod
    def get_next_work_required(
        cls,
        prev_block_hash: str,
        active_chain: BaseBlockChain,
        side_branches: Iterable[BaseBlockChain] = None,
    ) -> int:
        """
        Based on the chain, return the number of difficulty bits the next block
        must solve.
        """

        if not prev_block_hash:
            return Params.INITIAL_DIFFICULTY_BITS

        if side_branches is not None:

            (prev_block, prev_height, pre_chain_idx) = Block.locate_block(
                prev_block_hash, active_chain, side_branches
            )

            if pre_chain_idx != 0:
                return None

            if prev_height % Params.DIFFICULTY_PERIOD_IN_BLOCKS != 0:
                return prev_block.bits

            period_start_block = active_chain.chain[
                max(prev_height - Params.DIFFICULTY_PERIOD_IN_BLOCKS, 0)
            ]

        elif side_branches is None:

            prev_block, prev_height = active_chain.chain[-1], active_chain.height

            if prev_height % Params.DIFFICULTY_PERIOD_IN_BLOCKS != 0:
                return prev_block.bits

            period_start_block = active_chain.chain[
                max(prev_height - Params.DIFFICULTY_PERIOD_IN_BLOCKS, 0)
            ]

        else:
            pass

        actual_time_taken = prev_block.timestamp - period_start_block.timestamp

        if actual_time_taken < Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
            # Increase the difficulty
            return prev_block.bits + 1
        elif actual_time_taken > Params.DIFFICULTY_PERIOD_IN_SECS_TARGET:
            return prev_block.bits - 1
        else:
            # Wow, that's unlikely.
            return prev_block.bits

    def calculate_fees(self, utxo_set: BaseUTXO_Set) -> int:

        fee = 0

        def utxo_from_block(txin: TxIn):
            tx = [t.txouts for t in self.txns if t.id == txin.to_spend.txid]
            return tx[0][txin.to_spend.txout_idx] if tx else None

        def find_utxo(txin: TxIn):
            return utxo_set.utxoSet.get(txin.to_spend) or utxo_from_block(txin)

        for txn in self.txns[1:]:
            spent = sum(find_utxo(i).value for i in txn.txins)
            sent = sum(o.value for o in txn.txouts)
            fee += spent - sent

        if len(self.txns[1:]) > 0:
            logger.info(
                f"[ds] fees for {len(self.txns[1:])} non-coinbase transactions in this block: {fee}"
            )

        return fee

    def validate_block(
        self,
        active_chain: BaseBlockChain,
        utxo_set: BaseUTXO_Set,
        mempool: BaseMemPool = None,
        side_branches: Iterable[BaseBlockChain] = None,
    ) -> int:
        # logger.info(f'[p2p] already in another validate_block process')

        def _get_median_time_past(
            prev_block,
            prev_block_height,
            prev_block_chain_idx,
            num_last_blocks: int = 11,
        ) -> int:

            if Params.ACTIVE_CHAIN_IDX == prev_block_chain_idx:
                last_n_blocks = active_chain.chain[:prev_block_height][::-1][
                    :num_last_blocks
                ]
                if not last_n_blocks:
                    return 0
                return last_n_blocks[len(last_n_blocks) // 2].timestamp
            else:
                return 0
                # side_branches[prev_block_chain_idx-1]

        if not self.txns:
            raise BlockValidationError("txns empty")

        if self.timestamp - time.time() > Params.MAX_FUTURE_BLOCK_TIME:
            raise BlockValidationError("Block timestamp too far in future")

        if int(self.id, 16) > (1 << (256 - self.bits)):
            raise BlockValidationError("Block header doesn't satisfy bits")

        if [i for (i, tx) in enumerate(self.txns) if tx.is_coinbase] != [0]:
            raise BlockValidationError("First txn must be coinbase and no more")

        try:
            for i, txn in enumerate(self.txns):
                txn.validate_basics(as_coinbase=(i == 0))
        except TxnValidationError:
            logger.exception(
                f"[ds] Transaction {txn} in block {self.id} failed to validate"
            )
            raise BlockValidationError("Invalid txn {txn.id}")

        if MerkleNode.get_merkle_root_of_txns(self.txns).val != self.merkle_hash:
            raise BlockValidationError("Merkle hash invalid")

        if (
            not self.prev_block_hash
            and active_chain.height == 1
            and self.id == active_chain.chain[0].id
        ):
            # this block is the genesis block
            if self.timestamp >= int(time.time()):
                raise BlockValidationError(
                    f"timestamp of genesis block should not be newer than current time"
                )
            if self.bits != Params.INITIAL_DIFFICULTY_BITS:
                raise BlockValidationError(
                    f"bits of genesis block is incorrect, so the node cannot be builded successfully"
                )

            return Params.ACTIVE_CHAIN_IDX
        else:
            prev_block, prev_block_height, prev_block_chain_idx = Block.locate_block(
                self.prev_block_hash, active_chain, side_branches
            )

            if not prev_block:
                raise BlockValidationError(
                    f"prev block {self.prev_block_hash} not found in any chain",
                    to_orphan=self,
                )

            if self.timestamp <= _get_median_time_past(
                prev_block, prev_block_height, prev_block_chain_idx
            ):
                raise BlockValidationError("timestamp too old")

            # No more validation for a block getting attached to a branch.
            if prev_block_chain_idx != Params.ACTIVE_CHAIN_IDX:
                if prev_block == side_branches[prev_block_chain_idx - 1].chain[-1]:
                    return prev_block_chain_idx
                else:
                    return len(side_branches) + 1

            # Prev. block found in active chain, but isn't tip => new fork.
            elif prev_block != active_chain.chain[-1]:
                return 1 if side_branches is None else len(side_branches) + 1

        if (
            Block.get_next_work_required(
                self.prev_block_hash, active_chain, side_branches
            )
            != self.bits
        ):
            raise BlockValidationError("bits is incorrect")

        for txn in self.txns[1:]:
            try:
                # utxo_set.validate_txn(utxo_set, mempool, active_chain, siblings_in_block=self.txns[1:], allow_utxo_from_mempool=False)
                utxo_set.validate_txn(txn, mempool)
            except TxnValidationError:
                msg = f"[ds] {txn} failed to validate"
                logger.exception(msg)
                raise BlockValidationError(msg)
        if active_chain.height == 1:
            # the current block is the second block of active chain to be validated
            logger.info(f"[ds] begin to validate the genesis block")
            return active_chain.chain[0].validate_block(active_chain, utxo_set)

        return Params.ACTIVE_CHAIN_IDX
