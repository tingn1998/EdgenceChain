import binascii
import logging
import os
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
from ds.BaseUTXO_Set import BaseUTXO_Set
from ds.BaseMemPool import BaseMemPool
from ds.Transaction import Transaction

from params.Params import Params
from script import script

from utils.Errors import TxUnlockError
from utils.Errors import TxnValidationError
from utils.Errors import ChainFileLostError

logging.basicConfig(
    level=getattr(logging, os.environ.get("TC_LOG_LEVEL", "INFO")),
    format="[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


class UTXO_Set(BaseUTXO_Set):
    def __init__(self):
        # Mapping[(txid, txout_idx), (value, toaddr, txid, txout_idx, is_coinbase, height)]
        self.utxoSet: Mapping[OutPoint, UnspentTxOut] = {}

    def get(self):
        return self.utxoSet

    def add_to_utxo(self, txout, tx, idx, is_coinbase, height):
        utxo = UnspentTxOut(
            *txout, txid=tx.id, txout_idx=idx, is_coinbase=is_coinbase, height=height
        )

        # logger.info(f'adding tx outpoint {utxo.outpoint} to utxo_set')
        self.utxoSet[utxo.outpoint] = utxo

    def rm_from_utxo(self, txid, txout_idx):
        del self.utxoSet[OutPoint(txid, txout_idx)]

    @classmethod
    def find_utxo_in_list(cls, txin, txns) -> UnspentTxOut:
        txid, txout_idx = txin.to_spend
        try:
            txout = [t for t in txns if t.id == txid][0].txouts[txout_idx]
        except Exception:
            return None

        return UnspentTxOut(
            *txout, txid=txid, is_coinbase=False, height=-1, txout_idx=txout_idx
        )

    # we do script check process in this part
    def validate_txn(
        self,
        txn: Transaction,
        mempool: BaseMemPool = None,
        as_coinbase: bool = False,
        siblings_in_block: Iterable[NamedTuple] = None,  # object
        allow_utxo_from_mempool: bool = True,
    ) -> bool:
        def get_current_height(chainfile=Params.CHAIN_FILE):
            if not os.path.isfile(chainfile):
                raise ChainFileLostError("chain file not found")
            try:
                with open(chainfile, "rb") as f:
                    height = int(binascii.hexlify(f.read(4) or b"\x00"), 16)
            except Exception:
                logger.exception(f"[ds] read block height failed")
                return 0
            return height

        # pre-verify process
        txn.validate_basics(as_coinbase=as_coinbase)

        # check the fee
        available_to_spend = 0

        for idx, txin in enumerate(txn.txins):
            utxo = self.get().get(txin.to_spend)

            if siblings_in_block:
                utxo = utxo or UTXO_Set.find_utxo_in_list(txin, siblings_in_block)

            if allow_utxo_from_mempool:
                utxo = utxo or mempool.find_utxo_in_mempool(txin)

            # get utxo from the mempool for farther verify
            if not utxo:
                raise TxnValidationError(
                    f"Could find no UTXO for TxIn [{idx}] for txn: {txn.id}",
                    to_orphan=txn,
                )

            if (
                utxo.is_coinbase
                and (get_current_height() - utxo.height) < Params.COINBASE_MATURITY
            ):
                raise TxnValidationError(f"Coinbase UTXO not ready for spend")

            # do script check in this part!
            try:
                txio = script.Script(self.utxoSet, txn)
                valid = txio.verify()
                # temparary: produce new address to update the utxo.(ljq)
                # addresses = [txio.output_address(o) for o in range(0, txio.output_count)]
                if valid:
                    logger.info(f"[script] Script check succeed!")
                else:
                    logger.error(f"[script] Script check failed in Transaction part!")
                    raise TxnValidationError(f"Script check failed")
            except TxUnlockError:
                raise TxnValidationError(f"{txin} is not a valid spend of {utxo}")

            available_to_spend += utxo.value

        if available_to_spend < sum(o.value for o in txn.txouts):
            raise TxnValidationError("Spend value is more than available")

        return True
