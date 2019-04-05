
## Readme


Nowadays scalable IoT management is a bottleneck of IoT development due to the geographically dispersed distribution, fragmented ownerships, and ever-growing population of IoT devices. To intelligently manage massive decentralized applications (dApps) in IoT usecases, Edgence (EDGe + intelligENCE) uses edge clouds to access IoT devices and users, and then uses its in-built blockchain to realize self-governing and self-supervision of the edge clouds.

EdgenceChain is the blockchain part behind Edgence project. It helps to construct trust between different parties and personals in a self-authorized style.


## Ubuntu下节点启动方式

### 1.python3.6.7的安装
所需python环境 3.6.7， 下载地址 https://www.python.org/ftp/python/3.6.7/Python-3.6.7.tgz 
```
tar -xzf Python-3.6.7.tgz
cd Python-3.6.7
./configure --enable-optimizations  --prefix=/usr/local/python3.6.7/
#prefix参数配置安装路径
make 
sudo make install
```

### 2.python虚拟环境的启动和配置
在EdgenceChain工程目录下启动python虚拟环境
```
virtualenv --no-site-packages -p /usr/local/python3.6.7/bin/python3.6  venv
source venv/bin/activate
```
安装依赖
```
pip install -r requirements.txt
```

### 3.节点端口设置
1.当前结点端口的设置是在params/Params.py的PORT_CURRENT字段。 举例：将该节点的端口设置为9997： 
*PORT_CURRENT = int(9997)*

2.如果该节点要与已经在运行的EdgenceChain主网，则需要提前配置种子节点。其位于params/Params.py的PEERS字段，节点由一个Tuple类型的(ip,port)表示其ip和port信息。可以配置多个这样的节点。
*PEERS: Iterable[Tuple] = list([('127.0.0.1', 9997)])*

### 4.节点运行
在EdgenceChain工程目录下
```
python main.py
```
