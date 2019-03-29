from typing import (
    Iterable, NamedTuple, Dict, Mapping, Union, get_type_hints, Tuple,
    Callable)
import os,logging,binascii
#use regular expression to match non-IP
import re
import socket
from collections import namedtuple

logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

from params.Params import Params
from utils.Utils import Utils

class Peer(namedtuple("ip_port","ip,port")):

    def __call__(self):
        return str(self.ip), int(self.port)

    def __eq__(self, other):
        return isinstance(self, type(other)) and self.ip == other.ip and self.port == other.port

    def  __hash__(self):
        return hash(f'{self.ip}{self.port}')


    def __new__(cls,ip='0.0.0.0',port=9999):
        ip = str(ip)
        if re.match(r'(?<![\.\d])(?:25[0-5]\.|2[0-4]\d\.|[01]?\d\d?\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\.\d])',ip)==None:
            try:
                ip = socket.gethostbyname(ip.split('//')[-1].split('/')[0])
            except Exception:
                logger.exception(f"[p2p] {ip} can not be resolved , maybe not a valid name")
                return super().__new__(cls,'0.0.0.0',9999)

        else:
            pass

        if re.match(r'^(?<![\.\d])(?:25[0-5]\.|2[0-4]\d\.|[01]?\d\d?\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\.\d])$',ip)!=None and re.match(r'^([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{4}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$',str(port))!=None:
            return super().__new__(cls, ip, port) 
        else:
            logger.info(f'[p2p] init peers exception：{ip}:{port} is not a valid [ip]:[port]')
            return super().__new__(cls,'0.0.0.0',9999)


    @property
    def id(self):
        return Utils.sha256d(Utils.serialize(self))

    @classmethod
    def init_peers(cls, peerfile = Params.PEERS_FILE)->Iterable[NamedTuple]:
        if not os.path.exists(peerfile):
            peers: Iterable[Peer] =[]
            for peerlist in Params.PEERS:
                peer = Peer(str(peerlist[0]), int(peerlist[1]))
                if peer== Peer('127.0.0.1', Params.PORT_CURRENT) or \
                peer == Peer('localhost', Params.PORT_CURRENT) or \
                    peer.ip == '0.0.0.0' or \
                    peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                    pass
                else:
                    peers.append(peer)
            try:
                with open(peerfile, "wb") as f:
                    logger.info(f"[p2p] saving {len(peers)} hostnames")
                    f.write(Utils.encode_socket_data(list(peers)))
            except Exception:
                logger.exception(f'[p2p] saving peers exception')
                return []
        else:
            try:
                with open(peerfile, "rb") as f:
                    msg_len = int(binascii.hexlify(f.read(4) or b'\x00'), 16)
                    gs = dict()
                    gs['Peer'] = globals()['Peer']
                    peers = Utils.deserialize(f.read(msg_len), gs)
                    peers = list(set(peers))

                    length=len(peers)
                    idx=0
                    while idx < length:
                        peer = peers[idx]
                        if peer== Peer('127.0.0.1', Params.PORT_CURRENT) or \
                            peer == Peer('localhost', Params.PORT_CURRENT) or \
                            peer.ip == '0.0.0.0' or \
                             peer == Peer(Params.PUBLIC_IP, Params.PORT_CURRENT):
                            del peers[idx]
                            idx -= 1
                            length -= 1
                        idx += 1


                    logger.info(f"[p2p] loading peers with {len(peers)} hostnames")
            except Exception:
                logger.exception(f'[p2p] loading peers exception')
                peers = []
        return peers

    @classmethod
    def save_peers(cls, peers: Iterable[NamedTuple], peerfile = Params.PEERS_FILE):
        try:
            with open(peerfile, "wb") as f:
                logger.info(f"[p2p] saving {len(peers)} hostnames")
                f.write(Utils.encode_socket_data(list(peers)))
        except Exception:
            logger.exception('[p2p] saving peers exception')
