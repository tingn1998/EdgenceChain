from typing import NamedTuple, Union

from ds.OutPoint import OutPoint


class TxIn(NamedTuple):
    """Inputs to a Transaction."""

    # A reference to the output we're spending. This is None for coinbase
    # transactions.
    # Outpoint consist of [txid, txout_idx]
    to_spend: Union[OutPoint, None]

    # define scriptSig (unlocking script) here
    # the scriptSig which unlocks the TxOut for spending.
    signature_script: bytes

    # A sender-defined sequence number which allows us replacement of the txn
    # if desired.
    sequence: int
