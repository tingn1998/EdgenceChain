from typing import (NamedTuple, Union)

from ds.OutPoint import OutPoint

class TxIn(NamedTuple):
    """Inputs to a Transaction."""
    # A reference to the output we're spending. This is None for coinbase
    # transactions.
    to_spend: Union[OutPoint, None]

    # define scriptSig here
    # the scriptSig which un locks the TxOut for spending.

    signature_script: bytes

    # A sender-defined sequence number which allows us replacement of the txn
    # if desired.
    sequence: int
