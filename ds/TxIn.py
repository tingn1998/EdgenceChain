from typing import (NamedTuple, Union)

from ds.OutPoint import OutPoint


class TxIn(NamedTuple):
    """Inputs to a Transaction."""
    # A reference to the output we're spending(UTXO).
    # This is None for coinbase transactions.
    to_spend: Union[OutPoint, None]

    # temparary: OutPoint = NamedTuple('OutPoint', [('txid', str), ('txout_idx', int)]) address and index.

    # temparary: The (signature, pubkey) pair which unlocks the TxOut for spending.
    # temparary: unlock_sig: bytes
    # temparary: unlock_pk: bytes

    # define scriptSig and len here
    # the scriptSig which un locks the TxOut for spending.

    sig_len: int
    signature_script: str

    # A sender-defined sequence number which allows us replacement of the txn
    # if desired.
    sequence: int
