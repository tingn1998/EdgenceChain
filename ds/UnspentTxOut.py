from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)

from ds.OutPoint import OutPoint


class UnspentTxOut(NamedTuple):

    value: int

    # temprary: we need tx hash here；
    # txn_hash: str

    to_address: str

    # The ID of the transaction this output belongs to.
    txid: str
    txout_idx: int

    # pk_script(scriptPublicKey) for verify the transaction
    pk_script: str

    # Did this TxOut from from a coinbase transaction?
    is_coinbase: bool

    # The blockchain height this TxOut was included in the chain.
    height: int


    @property
    def outpoint(self):
        return OutPoint(self.txid, self.txout_idx)


