from typing import NamedTuple


class BlockStats(NamedTuple):
    """
    Global status of current blockchain.
    """
    height: int
    difficulty: float
    tx_pool_size: int
