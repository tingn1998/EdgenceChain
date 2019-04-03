import inspect
import struct
import logging
import os

from .bytevector import ByteVector
from . import opcodes

from . import scriptUtils

logging.basicConfig(
    level=getattr(logging, os.environ.get('TC_LOG_LEVEL', 'INFO')),
    format='[%(asctime)s][%(module)s:%(lineno)d] %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# two main classes in this package
__all__ = ['Script', 'Tokenizer']

# Convenient constants used to set the result of stack computing process
Zero = ByteVector.from_value(0)
One = ByteVector.from_value(1)

# ————————————————————tool functions———————————————————————

# check whether the opcode is a publickey for P2PK
def _is_pubkey(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 65 or data[0] != chr(0x04):
        return False
    return True


# check whether the opcode is a hash160 value for P2PKH
def _is_hash160(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 20:
        return False
    return True


def _is_hash256(opcode, bytes, data) -> bool:
    if opcode != Tokenizer.OP_LITERAL:
        return False
    if len(data) != 32:
        return False
    return True

# —————————————————————Script verify templates——————————————————————

SCRIPT_FORM_NON_STANDARD = 'non-standard'
SCRIPT_FORM_PAY_TO_PUBKEY_HASH = 'pay-to-pubkey-hash'  # P2PKH
SCRIPT_FORM_PAY_TO_PUBKEY = 'pay-to-pubkey'  # P2PK

# script templates
STANDARD_SCRIPT_FORMS = [
    SCRIPT_FORM_PAY_TO_PUBKEY_HASH,
    SCRIPT_FORM_PAY_TO_PUBKEY
]

# scriptSig template for P2PKH
TEMPLATE_PAY_TO_PUBKEY_HASH = (lambda t: len(t) == 5, opcodes.OP_DUP,
                               opcodes.OP_HASH160, _is_hash160, opcodes.OP_EQUALVERIFY,
                               opcodes.OP_CHECKSIG)

# scriptSig template for P2PKH
TEMPLATE_PAY_TO_PUBKEY = (lambda t: len(t) == 2, _is_pubkey,
                          opcodes.OP_CHECKSIG)

# a list of the templates for searching
Templates = [

    (SCRIPT_FORM_PAY_TO_PUBKEY_HASH, TEMPLATE_PAY_TO_PUBKEY_HASH),

    (SCRIPT_FORM_PAY_TO_PUBKEY, TEMPLATE_PAY_TO_PUBKEY),

    #    (SCRIPT_FORM_TRANSACTION_PUZZLE_HASH256,
    #     (lambda t: len(t) == 3,
    #      opcodes.OP_HASH256, _is_hash256, opcodes.OP_EQUAL)),
]

# ——————————————————————stack functions—————————————————————————

# use func to operate the stack
def _stack_op(stack, func) -> bool:
    """Replaces the top N items from the stack with the items in the list
       returned by the callable func; N is func's argument count

       The result must return a list.
    """

    # not enough arguments
    count = len(inspect.getfullargspec(func).args)
    if len(stack) < count:
        return False

    # pop process
    args = stack[-count:]
    stack[-count:] = []

    # process the func as a arg
    # add each returned item onto the stack
    for item in func(*args):
        stack.append(item)

    return True


# use func to do math operations on the stack
def _math_op(stack, func, check_overflow=True) -> bool:
    """Replaces the top N items from the stack with the result of the callable
       func; N is func's argument count.

       A boolean result will push either a 0 or 1 on the stack. None will push
       nothing.Otherwise, the result must be a ByteVector!!!
    """


    # not enough arguments
    count = len(inspect.getfullargspec(func).args)
    if len(stack) < count: return False
    args = stack[-count:]
    stack[-count:] = []

    # args no more than 4
    # check for overflow
    if check_overflow:
        for arg in args:
            if len(arg) > 4:
                return False

    # compute the result
    result = func(*args)

    # convert booleans to One or Zero
    if result == True:
        result = One
    elif result == False:
        result = Zero

    if result is not None:
        stack.append(result)

    return True


# use func to do hash operations on the stack
def _hash_op(stack, func) -> bool:
    """Replaces the top of the stack with the result of the callable func.

       The result must be a ByteVector.
    """

    # not enough arguments
    if len(stack) < 1:
        return False

    # hash and push
    value = func(stack.pop().vector)
    stack.append(ByteVector(value))

    return True

# ————————————————————process the signature—————————————————————————

def check_signature(signature, public_key, hash_type, subscript, transaction, input_index) -> bool:
    # figure out the hash_type and adjust the signature
    if hash_type == 0:
        hash_type = ord(signature[-1])
    signature = signature[:-1]

    # print(hash_type)

    # SIGHASH_ALL
    if (hash_type & 0x1f) == 0x01 or hash_type == 0:
        # print "ALL"
        tx_ins = []
        for (index, tx_in) in enumerate(transaction.inputs):
            script = ''
            if index == input_index:
                script = subscript # find the

            # form the new tx_ins
            tx_in = protocol.TxnIn(tx_in.previous_output, script, tx_in.sequence)
            tx_ins.append(tx_in)

        tx_outs = transaction.outputs

    # SIGHASH_NONE (other tx_in.sequence = 0, tx_out = [ ])

    # SIGHASH_SINGLE (len(tx_out) = input_index + 1, other outputs = (-1, ''), other tx_in.sequence = 0)

    else:
        raise Exception('Wrong hash type: %d' % hash_type)

    # SIGHASH_ANYONECANPAY
    if (hash_type & 0x80) == 0x80:
        # print "ANYONE"
        tx_in = transaction.inputs[input_index]
        tx_ins = [protocol.TxnIn(tx_in.previous_output, subscript, tx_in.sequence)]

        tx_outs = transaction.outputs

    # build the new message
    tx_copy = FlexTxn(transaction.version, tx_ins, tx_outs, transaction.lock_time)

    # ——————————————compute the data to verify————————————————

    # compute the hash value of the signature
    sig_hash = struct.pack('<I', hash_type) # str type

    # rebuild the data
    payload = tx_copy.binary() + sig_hash

    return # verify process


# this class is used to form a output using the outputs' template
# identical to the main Txn except it allows zero tx_out for SIGHASH_NONE!!!
class FlexTxn(protocol.Txn):
    @TODO


# ————————————————————tool class producing tokens[]——————————————————————————

# test examples:
    # txid: 370b0e8298cf00b47a61ebac3381d38f38f62b065ef5d8dd3cfd243e4b6e9137 (input# 0)
    # >>> pk_script = 'v\xa9\x14\xd6Kqr\x9aPM#\xd9H\x88\xd3\xf7\x12\xd5WS\xd5\xd6"\x88\xac'
    # >>> print pycoind.Tokenizer(pk_script)
    # OP_DUP OP_HASH160 d64b71729a504d23d94888d3f712d55753d5d622 OP_EQUALVERIFY OP_CHECKSIG


class Tokenizer(object):
    """
    Tokenizes a script into tokens for the checking process of stack.
    """

    OP_LITERAL = 0x1ff

    ### Init part
    def __init__(self, script, expand_verify=False):
        self._script = script
        self._expand_verify = expand_verify
        self._tokens = []
        self._process(script)

    # when we add another part we also check for it.
    def append(self, script):
        self._script += script
        self._process(script)


    # map used to check the final opcode.
    _Verify = {
        opcodes.OP_EQUALVERIFY: opcodes.OP_EQUAL,
        opcodes.OP_NUMEQUALVERIFY: opcodes.OP_NUMEQUAL,
        opcodes.OP_CHECKSIGVERIFY: opcodes.OP_CHECKSIG,
        opcodes.OP_CHECKMULTISIGVERIFY: opcodes.OP_CHECKMULTISIG,
    }

    # it's checked by final check-function
    def get_subscript(self, start_index=0, filter=None) -> str:
        """The function is used to check the script value with the filter (opcode,bytes,value)"""

        output = ''
        for (opcode, bytes, value) in self._tokens[start_index:]:
            # check the value
            if filter and not filter(opcode, bytes, value):
                continue
            output += bytes
        # return the checked script
        return output

    # Given a template, return True if this script matches
    def match_template(self, template) -> bool:

        if not template[0](self):
            return False

        # ((opcode, bytes, value), template_target)
        for ((o, b, v), t) in zip(self._tokens, template[1:]):

            # callable, check the value
            if callable(t):
                if not t(o, b, v):
                    return False

            # otherwise, compare opcode
            elif t != o:
                return False

        return True

    # Get the original bytes used for the opcode and value
    def get_bytes(self, index) -> bytes:
        return self._tokens[index][1]

    # Get the value for a literal.
    def get_value(self, index) -> str:
        return self._tokens[index][2]

    # Internal function which parse the script into tokens
    def _process(self, script):

        while script:

            # process one code from scripts every time
            opcode = ord(script[0])
            bytes = script[0]
            script = script[1:]

            value = None
            verify = False

            if opcode == opcodes.OP_0:
                value = Zero
                opcode = Tokenizer.OP_LITERAL

            # push data options
            elif 1 <= opcode <= 78:
                length = opcode

                if opcodes.OP_PUSHDATA1 <= opcode <= opcodes.OP_PUSHDATA4:
                    op_length = [1, 2, 4][opcode - opcodes.OP_PUSHDATA1]
                    format = ['<B', '<H', '<I'][opcode - opcodes.OP_PUSHDATA1]
                    length = struct.unpack(format, script[:op_length])[0]
                    bytes += script[:op_length]
                    script = script[op_length:] # pop the data from script by length

                value = ByteVector(vector=script[:length])
                bytes += script[:length]
                script = script[length:]
                if len(value) != length:
                    raise Exception('not enough script for literal')
                opcode = Tokenizer.OP_LITERAL

            elif opcode == opcodes.OP_1NEGATE:
                opcode = Tokenizer.OP_LITERAL
                value = ByteVector.from_value(-1)

            elif opcode == opcodes.OP_TRUE:
                opcode = Tokenizer.OP_LITERAL
                value = ByteVector.from_value(1)

            elif opcodes.OP_1 <= opcode <= opcodes.OP_16:
                value = ByteVector.from_value(opcode - opcodes.OP_1 + 1)
                opcode = Tokenizer.OP_LITERAL

            elif self._expand_verify and opcode in self._Verify:
                opcode = self._Verify[opcode]
                verify = True

            self._tokens.append((opcode, bytes, value))

            if verify:
                self._tokens.append((opcodes.OP_VERIFY, '', None))

    def __len__(self):
        return len(self._tokens)

    def __getitem__(self, name):
        return self._tokens[name][0]

    def __iter__(self):
        for (opcode, bytes, value) in self._tokens:
            yield opcode

    def __str__(self):
        output = []
        for (opcode, bytes, value) in self._tokens:
            if opcode == Tokenizer.OP_LITERAL:
                output.append(value.vector.encode('hex'))
            else:
                if bytes:
                    output.append(opcodes.get_opcode_name(ord(bytes[0])))

        return " ".join(output)

# —————————————————————— main stack Process————————————————————

class Script(object):

    def __init__(self, transaction):
        self._transaction = transaction

    def input_count(self) -> int:
        return len(self._transaction.inputs)

    # matching the template(P2PKH or P2PK)
    def script_form(self, output_index) -> str:
        pk_script = self._transaction.outputs[output_index].pk_script
        tokens = Tokenizer(pk_script)
        for (sf, template) in Templates:
            if tokens.match_template(template):
                return sf
        return SCRIPT_FORM_NON_STANDARD

    # should I use this?(@author ljq)
    def is_standard_script(self, output_index) -> bool:
        pk_script = self._transaction.outputs[output_index]
        tokens = Tokenizer(pk_script, expand_verify=False)
        for sf in STANDARD_SCRIPT_FORMS:
            if tokens.match_template(Templates[sf]):
                return True
        return False

    @property
    def output_count(self) -> int:
        return len(self._transaction.outputs)

    def output_address(self, output_index) -> str:

        # get the script
        pk_script = self._transaction.outputs[output_index].pk_script
        # get tokens for script
        tokens = Tokenizer(pk_script)

        # matching the template(P2PKH or P2PK)
        if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY_HASH):
            pubkeyhash = tokens.get_value(2).vector
            return scriptUtils.pubkeyhash_to_address(pubkeyhash, self._coin.address_version)

        if tokens.match_template(TEMPLATE_PAY_TO_PUBKEY):
            pubkey = tokens.get_value(0).vector
            return scriptUtils.publickey_to_address(pubkey, self._coin.address_version)

        return None

    # verify one input: need (idx,pk)
    def verify_input(self, input_index, pk_script) -> bool:

        input = self._transaction.inputs[input_index]
        # ——————————————————————do process function！———————————————————————
        return self.process(input.signature_script, pk_script, self._transaction, input_index)

    def verify(self) -> bool:
        """Return True if all transaction inputs can be verified against their
           previous output."""

        for i in range(0, len(self._transaction.inputs)):

            # ignore the coin_base (generation transaction input)
            if self._transaction.index == 0 and i == 0:
                continue

            # verify the input with its previous output
            previous_output = self._transaction.previous_output(i)
            if not self.verify_input(i, previous_output.pk_script): # get the previous output's pk_script
                # print "INVALID:", self._transaction.hash.encode('hex'), i # check for this
                logger.exception(f'[script] script verification wrong in Script part!')
                return False

        return True

    # Notice: lots of the process in the method is a regular process of bit-coin script language
    @staticmethod
    def process(signature_script, pk_script, transaction, input_index, hash_type=0):

        # tokenize (placing the last code separator after the signature script)
        # (input.signature_script）
        tokens = Tokenizer(signature_script, expand_verify=True)
        signature_length = len(tokens)
        # counting the length of tokens which contains two kind of scripts
        last_codeseparator = signature_length
        # (previous_output.pk_script）
        tokens.append(pk_script)


        # check for VERY forbidden opcodes (see "reserved Words" on the wiki)
        for token in tokens:
            if token in (opcodes.OP_VERIF, opcodes.OP_VERNOTIF):
                return False

        # stack of entered if statments' condition values
        ifstack = []

        # operating stacks
        stack = []
        altstack = []

        # ！！！do stack-unlock process！！！
        for pc in range(0, len(tokens)):  # counting process

            # get the opcodes
            opcode = tokens[pc]

            # handle if before anything else
            # check whether to stop the txn
            if opcode == opcodes.OP_IF:  # process if the stack top value is 0
                ifstack.append(stack.pop().value != 0)

            elif opcode == opcodes.OP_NOTIF:  # process if the stack top value isn't 0
                ifstack.append(stack.pop().value == 0)

            elif opcode == opcodes.OP_ELSE:  # process if OP_IF and OP_NOTIF flag don't work
                if len(ifstack) == 0: return False
                ifstack.push(not ifstack.pop())

            elif opcode == opcodes.OP_ENDIF:  # stop the three process flag above
                if len(ifstack) == 0: return False
                ifstack.pop()

            # we are in a branch with a false condition
            if False in ifstack:
                continue

            ### Literals

            if opcode == Tokenizer.OP_LITERAL:
                stack.append(tokens.get_value(pc))

            ### Flow Control (OP_IF and kin are above)

            elif opcode == opcodes.OP_NOP:
                pass

            elif opcode == opcodes.OP_VERIFY:
                if len(stack) < 1: return False
                if bool(stack[-1]):
                    stack.pop()
                else:
                    return False

            elif opcode == opcodes.OP_RETURN:
                return False

            ### Stack Operations

            elif opcode == opcodes.OP_TOALTSTACK:
                if len(stack) < 1: return False
                altstack.append(stack.pop())

            elif opcode == opcodes.OP_FROMALTSTACK:
                if len(altstack) < 1: return False
                stack.append(altstack.pop())

            elif opcode == opcodes.OP_IFDUP:
                if len(stack) < 1: return False
                if bool(stack[-1]):
                    stack.append(stack[-1])

            elif opcode == opcodes.OP_DEPTH:
                stack.append(ByteVector.from_value(len(stack)))

            elif opcode == opcodes.OP_DROP:
                if not _stack_op(stack, lambda x: []):
                    return False

            elif opcode == opcodes.OP_DUP:  # !!it's important for P2PKH
                if not _stack_op(stack, lambda x: [x, x]):
                    return False

            elif opcode == opcodes.OP_NIP:
                if not _stack_op(stack, lambda x1, x2: [x2]):
                    return False

            elif opcode == opcodes.OP_OVER:
                if not _stack_op(stack, lambda x1, x2: [x1, x2, x1]):
                    return False

            elif opcode == opcodes.OP_PICK:
                if len(stack) < 2: return False
                n = stack.pop().value + 1
                if not (0 <= n <= len(stack)): return False
                stack.append(stack[-n])

            elif opcode == opcodes.OP_ROLL:
                if len(stack) < 2: return False
                n = stack.pop().value + 1
                if not (0 <= n <= len(stack)): return False
                stack.append(stack.pop(-n))

            elif opcode == opcodes.OP_ROT:
                if not _stack_op(stack, lambda x1, x2, x3: [x2, x3, x1]):
                    return False

            elif opcode == opcodes.OP_SWAP:
                if not _stack_op(stack, lambda x1, x2: [x2, x1]):
                    return False

            elif opcode == opcodes.OP_TUCK:
                if not _stack_op(stack, lambda x1, x2: [x2, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2DROP:
                if not _stack_op(stack, lambda x1, x2: []):
                    return False

            elif opcode == opcodes.OP_2DUP:
                if not _stack_op(stack, lambda x1, x2: [x1, x2, x1, x2]):
                    return False

            elif opcode == opcodes.OP_3DUP:
                if not _stack_op(stack, lambda x1, x2, x3: [x1, x2, x3, x1, x2, x3]):
                    return False

            elif opcode == opcodes.OP_2OVER:
                if not _stack_op(stack, lambda x1, x2, x3, x4: [x1, x2, x3, x4, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2ROT:
                if not _stack_op(stack, lambda x1, x2, x3, x4, x5, x6: [x3, x4, x5, x6, x1, x2]):
                    return False

            elif opcode == opcodes.OP_2SWAP:
                if not _stack_op(stack, lambda x1, x2, x3, x4: [x3, x4, x1, x2]):
                    return False

            ### Splice Operations

            elif opcode == opcodes.OP_SIZE:
                if len(stack) < 1: return False
                stack.append(ByteVector.from_value(len(stack[-1])))

            ### Bitwise Logic Operations

            elif opcode == opcodes.OP_EQUAL:  # !!it's important for P2PKH
                if not _math_op(stack, lambda x1, x2: bool(x1 == x2), False):
                    return False

            ### Arithmetic Operations

            elif opcode == opcodes.OP_1ADD:
                if not _math_op(stack, lambda a: a + One):
                    return False

            elif opcode == opcodes.OP_1SUB:
                if not _math_op(stack, lambda a: a - One):
                    return False

            elif opcode == opcodes.OP_NEGATE:
                if not _math_op(stack, lambda a: -a):
                    return False

            elif opcode == opcodes.OP_ABS:
                if not _math_op(stack, lambda a: abs(a)):
                    return False

            elif opcode == opcodes.OP_NOT:
                if not _math_op(stack, lambda a: bool(a == 0)):
                    return False

            elif opcode == opcodes.OP_0NOTEQUAL:
                if not _math_op(stack, lambda a: bool(a != 0)):
                    return False

            elif opcode == opcodes.OP_ADD:
                if not _math_op(stack, lambda a, b: a + b):
                    return False

            elif opcode == opcodes.OP_SUB:
                if not _math_op(stack, lambda a, b: a - b):
                    return False

            elif opcode == opcodes.OP_BOOLAND:
                if not _math_op(stack, lambda a, b: bool(a and b)):
                    return False

            elif opcode == opcodes.OP_BOOLOR:
                if not _math_op(stack, lambda a, b: bool(a or b)):
                    return False

            elif opcode == opcodes.OP_NUMEQUAL:
                if not _math_op(stack, lambda a, b: bool(a == b)):
                    return False

            elif opcode == opcodes.OP_NUMNOTEQUAL:
                if not _math_op(stack, lambda a, b: bool(a != b)):
                    return False

            elif opcode == opcodes.OP_LESSTHAN:
                if not _math_op(stack, lambda a, b: bool(a < b)):
                    return False

            elif opcode == opcodes.OP_GREATERTHAN:
                if not _math_op(stack, lambda a, b: bool(a > b)):
                    return False

            elif opcode == opcodes.OP_LESSTHANOREQUAL:
                if not _math_op(stack, lambda a, b: bool(a <= b)):
                    return False

            elif opcode == opcodes.OP_GREATERTHANOREQUAL:
                if not _math_op(stack, lambda a, b: bool(a >= b)):
                    return False

            elif opcode == opcodes.OP_MIN:
                if not _math_op(stack, lambda a, b: min(a, b)):
                    return False

            elif opcode == opcodes.OP_MAX:
                if not _math_op(stack, lambda a, b: max(a, b)):
                    return False

            elif opcode == opcodes.OP_WITHIN:
                if not _math_op(stack, lambda x, omin, omax: bool(omin <= x < omax)):
                    return False

            ### Crypto Operations

            elif opcode == opcodes.OP_RIPEMD160:
                if not _hash_op(stack, scriptUtils.ripemd160):
                    return False

            elif opcode == opcodes.OP_SHA1:
                if not _hash_op(stack, scriptUtils.sha1):
                    return False

            elif opcode == opcodes.OP_SHA256:
                if not _hash_op(stack, scriptUtils.sha256):
                    return False

            elif opcode == opcodes.OP_HASH160:
                if not _hash_op(stack, scriptUtils.hash160):
                    return False

            elif opcode == opcodes.OP_HASH256:
                if not _hash_op(stack, scriptUtils.sha256d):
                    return False

            elif opcode == opcodes.OP_CODESEPARATOR:
                if pc > last_codeseparator:
                    last_codeseparator = pc

            # see: https://en.bitcoin.it/wiki/OP_CHECKSIG

            ### !!Begin to check for P2PKH!!

            elif opcode == opcodes.OP_CHECKSIG:  # check and remove thing from the stack
                if len(stack) < 2: return False

                # remove the signature and code separators for subscript
                def filter(opcode, bytes, value):
                    if opcode == opcodes.OP_CODESEPARATOR:
                        return False
                    if opcode == Tokenizer.OP_LITERAL and isinstance(value, str) and value == signature:
                        return False
                    return True

                subscript = tokens.get_subscript(last_codeseparator, filter)

                # the public_key and signature is the value remains in the stack
                public_key = stack.pop().vector
                signature = stack.pop().vector
                # use the check_signature defined in this package
                valid = check_signature(signature, public_key, hash_type, subscript, transaction, input_index)

                if valid:
                    stack.append(One) # the verify process is successful
                else:
                    stack.append(Zero)

            # This part checks the opcode for Muti-process
            # We don't use this part due to our plan
            # and it's easy to add this part.
            elif opcode == opcodes.OP_CHECKMULTISIG:
                if len(stack) < 2: return False

                # get all the public keys
                count = stack.pop().value
                if len(stack) < count: return False
                public_keys = [stack.pop() for i in range(count)]

                if len(stack) < 1: return False

                # get all the signautres
                count = stack.pop().value
                if len(stack) < count: return False
                signatures = [stack.pop() for i in range(count)]

                # due to a bug in the original client, discard an extra operand
                if len(stack) < 1: return False
                stack.pop()

                # remove the signature and code separators for subscript
                def filter(opcode, bytes, value):
                    if opcode == opcodes.OP_CODESEPARATOR:
                        return False
                    if opcode == Tokenizer.OP_LITERAL and isinstance(value, str) and value in signatures:
                        return False
                    return True

                subscript = tokens.get_subscript(last_codeseparator, filter)

                matched = dict()
                for signature in signatures:

                    # do any remaining public keys work?
                    for public_key in public_keys:
                        if check_signature(signature, public_key, hash_type, subscript, transaction, input_index):
                            break
                    else:
                        public_key is None

                    # record which public key and remove from future canidate
                    if public_key is not None:
                        matched[signature] = public_key
                        public_keys.remove(public_key)

                # did each signature have a matching public key?
                if len(matched) == len(signatures):
                    stack.append(One)
                else:
                    stack.append(Zero)

            elif opcode == opcodes.OP_RESERVED:
                return False

            elif opcode == opcodes.OP_VER:
                return False

            elif opcode == opcodes.OP_RESERVED1:
                return False

            elif opcode == opcodes.OP_RESERVED2:
                return False

            elif opcodes.OP_NOP1 <= opcode <= opcodes.OP_NOP10:
                pass

            else:
                # print "UNKNOWN OPCODE: %d" % opcode
                return False

        # check whether the stack process's result remains a True boolean type
        if len(stack) and bool(stack[-1]):
            return True

        return False