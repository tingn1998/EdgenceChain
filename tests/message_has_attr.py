from p2p.Message import Message
from p2p.Message import Actions

message = Message(0,'22',9991)

print(hasattr(message, "action"))

print(Actions.num2name[str(Actions.BlockRev)])



