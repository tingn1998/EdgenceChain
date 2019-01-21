# Edgencechain

## Readme


Edgencechain is a pocket-sized implementation of Bitcoin. Its goal is to
be a compact, understandable, working incarnation of 
[the Nakamoto consensus algorithm](https://github.com/EdgeIntelligenceChain/Materials2Study/blob/master/%E6%AF%94%E7%89%B9%E5%B8%81%E7%99%BD%E7%9A%AE%E4%B9%A6.pdf) at the
expense of advanced functionality, speed, and any real usefulness.


## 如何运行（环境要求: Ubuntu 16.04, and Python version >= 3.6.7）

#### 单node运行

+  python3 main.py


#### 在同一台物理机或虚拟机上多nodes运行

+ 每个node要有一份独立的代码拷贝，并且要配置一个未被占用的端口。端口的设置是在params/Params.py的PORT_CURRENT字段。
  举例：将该节点的端口设置为9997： * PORT_CURRENT = int(9997)* 
+ 如果该节点要与已经在运行的节点连接，则必须配置该参数，该参数位于params/Params.py的PEERS字段，节点由一个Tuple类型的(ip,port)表示其ip和port信息。可以配置多个这样的节点。
   PEERS: Iterable[Tuple] = list([('127.0.0.1', 9997)])



