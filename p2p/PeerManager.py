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
from bitarray import bitarray

from p2p.Peer import Peer
from params.Params import Params


import operator
import random

import logging
import os

logging.basicConfig(
    level=getattr(logging, os.environ.get("TC_LOG_LEVEL", "INFO")),
    format="[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


class PeerState(NamedTuple):

    peer: Peer
    # log represents previous connect info.
    log: bitarray
    isBlocked: bool = False

    @property
    def count_1(self):
        # 1 represents connect not success.
        return self.log.count(1)


class PeerManager(object):
    def __init__(
        self,
        peers: Iterable[Peer] = [],
        peer_number_limit: int = 15,
        state_number_limit: int = Params.MAXIMUM_FAILURE_PEER,
    ):

        self.state_number_limit = int(state_number_limit)
        self.peer_number_limit = int(peer_number_limit)

        self.black_list: Iterable[Peer] = []

        # Peer info and peer state. Value type: PeerState
        self.peerstate_list = []

        # If peers in peerlist are more than peer_number_limit,
        # Use the first peer_number_limit's peer.
        if len(peers) > self.peer_number_limit:
            peers = peers[: self.peer_number_limit]

        # Initialize bitarray for all peers = "000000...000"
        for peer in peers:
            self.peerstate_list.append(
                PeerState(peer, bitarray("0" * self.state_number_limit))
            )
        logger.info(f"[p2p] loading {len(peers)} peers into PeerManager")

    def addLog(self, peer: Peer, not_success: int = 0) -> None:

        if not_success != 0:
            not_success = 1

        for idx, peerstate in enumerate(self.peerstate_list, 0):
            if peerstate.peer == peer:
                # Right shift 1 bit and set first bit equals to param: not_success
                peerstate.log[1:] = peerstate.log[:-1]
                peerstate.log[0] = not_success
                
                # If all bits in bitarray is True (equals to 1),
                # mark this peer as Blocked.
                if peerstate.log.all() and peerstate.isBlocked == False:
                    self.peerstate_list[idx] = self.peerstate_list[idx]._replace(
                        isBlocked=True
                    )
                
                # If this peer previous is blocked and now it can be accessed,
                # mark this peer as not Blocked.
                if not not_success and peerstate.isBlocked == True:
                    self.peerstate_list[idx] = self.peerstate_list[idx]._replace(
                        isBlocked=False
                    )

                # operator.attrgetter is an alternative to lambda function. But operator.attrgetter
                # allows more than one word to compare.
                # Use isBlocked and count_1 as sorted key in order.
                # Peer with better connectivity will be placed at the front of the list.
                self.peerstate_list.sort(
                    key=operator.attrgetter("isBlocked", "count_1")
                )

    def add(self, peer: Peer) -> None:
        """
        Add peer into peermanager. 
        """

        for peerstate in self.peerstate_list:
            if peerstate.peer == peer:
                logger.info(f"[p2p] {peer} is already in PeerManager")
                return

        if peer not in self.black_list:
            if len(self.peerstate_list) == self.peer_number_limit:
                # If the last peer is not blocked, all peer are not blocked.
                if self.peerstate_list[-1].isBlocked:
                    self.peerstate_list[-1] = PeerState(
                        peer, bitarray("0" * self.state_number_limit)
                    )
                else:
                    logger.info(
                        f"[p2p] can not add more peers like {peer} into PeerManager"
                    )
                    return
            else:
                self.peerstate_list.append(
                    PeerState(peer, bitarray("0" * self.state_number_limit))
                )
            logger.info(f"[p2p] adding {peer} into PeerManager")
            self.peerstate_list.sort(key=operator.attrgetter("isBlocked", "count_1"))

    def remove(self, peer: Peer) -> None:
        """
        If peer in peerlist, remove it from peerlistand add it to black_list, 
        else if in block_list, remove it from black_list.
        """

        if peer in self.black_list:
            self.black_list.remove(peer)
            logger.info(f"[p2p] remove {peer} from black list of PeerManager")

        for peerstate in self.peerstate_list:
            if peerstate.peer == peer:
                self.peerstate_list.remove(peerstate)
                if peer not in self.black_list:
                    self.black_list.append(peer)
                    logger.info(
                        f"[p2p] remove {peer} from peerstate_list and add it into blacklist of PeerManager"
                    )
                else:
                    logger.info(
                        f"[p2p] remove {peer} from peerstate_list and find it in blacklist of PeerManager"
                    )

    def block(self, peer: Peer) -> None:
        """
        If peer in black_list, remove it form black_list,
        else set peerstate: isBlocked = True, set log to all "1".
        """

        if peer in self.black_list:
            self.black_list.remove(peer)

        # 0 represents starting with the first item in peerstate_list.
        for idx, peerstate in enumerate(self.peerstate_list, 0):
            if peerstate.peer == peer:
                self.peerstate_list[idx] = peerstate._replace(
                    isBlocked=True, log=bitarray("1" * self.state_number_limit)
                )
                logger.info(f"[p2p] block {peer} in PeerManager")
                self.peerstate_list.sort(
                    key=operator.attrgetter("isBlocked", "count_1")
                )

    def update(self, bits: int = 1) -> None:
        """
        Update all peer by block log.
        Set first [bits] bits equal to 0 for all blocked peer.
        """

        if bits > self.state_number_limit:
            bits = self.state_number_limit

        for idx, peerstate in enumerate(self.peerstate_list, 0):
            if peerstate.isBlocked:
                peerstate.log[bits:] = peerstate.log[:-bits]
                peerstate.log[:bits] = 0
            
            # If not all bits are "1", represents that this peer is not blocked,
            # Set isBlocked = False.
            if not peerstate.log.any() and peerstate.isBlocked:
                self.peerstate_list[idx] = peerstate._replace(isBlocked=False)
                logger.info(
                    f"[p2p] {peerstate.peer} is unblocked in updating of PeerManager"
                )

        self.peerstate_list.sort(key=operator.attrgetter("isBlocked", "count_1"))

        # Useless below.
        # 
        # unblocked_list = [
        #     peerstate.peer
        #     for peerstate in self.peerstate_list
        #     if not peerstate.isBlocked
        # ]
        # if unblocked_list:
        #    logger.info(f'unblocked peer list is: {unblocked_list}')

    def getPeers(self, number: int = 0) -> Iterable[Peer]:
        """
        Get peers from peerlist, default param value = 0 represents
        get all peers that are not blocked.
        """

        number_not_blocked = 0
        for idx in range(len(self.peerstate_list)):
            if not self.peerstate_list[idx].isBlocked:
                number_not_blocked += 1

        if number == 0:
            number = number_not_blocked
        if number > len(self.peerstate_list):
            number = len(self.peerstate_list)

        peers = []

        if number > number_not_blocked:
            for idx in range(number):
                peerstate = self.peerstate_list[idx]
                peers.append(peerstate.peer)
            # logger.info(f'[p2p] wanted number {number} is larger than number of unblocked peers {number_not_blocked} in PeerManager')
        else:
            selected_idxs = random.sample(range(number_not_blocked), number)
            for idx in selected_idxs:
                peerstate = self.peerstate_list[idx]
                peers.append(peerstate.peer)
            # logger.info(f'[p2p] wanted number {number} is less than or equal to number of unblocked peers {number_not_blocked} in PeerManager')

        return peers

    def getAllPeers(self) -> Iterable[Peer]:
        peers = []
        for peerstate in self.peerstate_list:
            peers.append(peerstate.peer)

        return peers
