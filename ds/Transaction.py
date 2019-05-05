from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, Tuple,
    Callable)

from utils.Errors import TxnValidationError

from utils.Utils import Utils
from params.Params import Params
from ds.TxIn import TxIn
from ds.TxOut import TxOut

from script import scriptBuild

import logging
import os



logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# Used to represent the specific output within a transaction.

class Transaction(NamedTuple):
    txins: Iterable[TxIn]
    txouts: Iterable[TxOut]


    locktime: int = None

    @property
    def is_coinbase(self) -> bool:
        return len(self.txins) == 1 and self.txins[0].to_spend is None

    @classmethod
    def create_coinbase(cls, pay_to_addr, value, height):
        return cls(
            txins=[TxIn(
                to_spend=None,
                # Push current block height into unlock_sig so that this
                # transaction's ID is unique relative to other coinbase txns.
                # first param is unlock_sig, another is unlock_pk
                signature_script=scriptBuild.get_signature_script_without_hashtype(str(height).encode(), b'')
                if Params.SCRIPT_TYPE == 0 else scriptBuild.get_signature_script_without_hashtype([str(height).encode()], b''),
                sequence=0)],
            txouts=[TxOut(
                value=value,
                pk_script=scriptBuild.get_pk_script(pay_to_addr)
            )],
        )

    @property
    def id(self) -> str:
        return Utils.sha256d(Utils.serialize(self))

    def validate_basics(self, as_coinbase=False):
        if not self.txouts:
            raise TxnValidationError('Missing txouts')
        if not as_coinbase and not self.txins:
            raise TxnValidationError('MIssing txins for not coinbase transation')
        if not as_coinbase:
            if None in [txin.to_spend for txin in self.txins]:
                raise TxnValidationError('None to spend for not coinbase transation')
        if as_coinbase and len(self.txins)>1:
            raise TxnValidationError('Coinbase transaction has more than one TxIns')
        if as_coinbase and self.txins[0].to_spend is not None:
            raise TxnValidationError('Coinbase transaction should not have valid to_spend in txins')

        if len(Utils.serialize(self)) > Params.MAX_BLOCK_SERIALIZED_SIZE:
            raise TxnValidationError('Too large')

        if sum(t.value for t in self.txouts) > Params.MAX_MONEY:
            raise TxnValidationError('Spend value too high')
