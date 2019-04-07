from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)


class TxOut(NamedTuple):
    """Outputs from a Transaction."""
    # The number of LET this awards.
    value: int

    # temparary: The public key of the owner of this Txn.
    # temparary: to_address: str

    # define pk_script(scriptPublicKey) here
    pk_script: str
