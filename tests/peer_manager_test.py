from p2p.PeerManager import PeerManager
from p2p.PeerManager import PeerState
from p2p.Peer import Peer
from bitarray import bitarray

peerManager = PeerManager(state_number_limit = 5, peer_number_limit = 3)

#peerState1 = PeerState(Peer('11','0'))


peerManager.add(Peer('12','0'))
peerManager.add(Peer('11','0'))
peerManager.add(Peer('15','0'))

peerManager.update()
print(peerManager.peerstate_list)


peerManager.peerstate_list[0] = peerManager.peerstate_list[0]._replace(isBlocked=True)
peerManager.update()
print(peerManager.peerstate_list)
#peerManager.addLog(Peer('11','0'), 0)
peerManager.update()
print(peerManager.peerstate_list)
peerManager.update()
print(peerManager.peerstate_list)

a = [True, False, True, False]
a.sort()
print(a)




#for i in range(60):

#    peerManager.update()#



