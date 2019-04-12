from script import script
from script import scriptBuild


public_hash = b'f256f3f62388e17b66e881f80b17a69dfc55b7e4'

# from hash to pk_script
res = scriptBuild.get_pk_script(public_hash)
print(res)

# from pk_script to tokens
print(script.Tokenizer(res))
