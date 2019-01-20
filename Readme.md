# Edgencechain

## Readme


Edgencechain is a pocket-sized implementation of Bitcoin. Its goal is to
be a compact, understandable, working incarnation of 
[the Nakamoto consensus algorithm](https://github.com/EdgeIntelligenceChain/Materials2Study/blob/master/%E6%AF%94%E7%89%B9%E5%B8%81%E7%99%BD%E7%9A%AE%E4%B9%A6.pdf) at the
expense of advanced functionality, speed, and any real usefulness.

## How to play

#### single node run

+  python3 main.py


#### several nodes communication

+ the node's port can be set in params/Params.py using:
  * PORT_CURRENT = int(9997)* 
  which means the node's port is 9997.
+ when the node is running, its ip and port together identify itself.
  suppose the node #A has a ip with 127.0.0.1 and port 9997. When another node #B wants to connect it,
  then node #B should modify the PEERS in params/Params by:
   PEERS: Iterable[Tuple] = list([('127.0.0.1', 9997)])


