from p2p.Peer import Peer

peer1 = Peer()
print(peer1)
peer2 = Peer('10.108.01.13')
print(peer2)
peer3 = Peer('10.108.01.13',18)
print(peer3)

print(peer1.__eq__(peer2))
print(peer2.__eq__(Peer('10.108.01.13', 9999)))
print(peer1 == peer2)
print(peer2 == Peer('10.108.01.13', 9999))

print(peer1.__eq__(peer2))
print(peer2.__eq__(Peer('10.108.01.13', 9999)))
print(peer1 == peer2)
print(peer2 == Peer('10.108.01.13', 9999))

print(Peer('127.0.0.1', 1000) == Peer('localhost', 1000))
