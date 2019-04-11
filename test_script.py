import unittest
from script import script

class TestScriptTransactions(unittest.TestCase):

    def check_script(self, script, output):
        # for each output, add the literal and do checkverify
        if output:
            for o in reversed(output):
                if isinstance(o, int):
                    # o is a signed int so it needs a bit more
                    length = (o.bit_length() + 7 + 1) // 8
                    script += length.to_bytes(1, 'big') + o.to_bytes(length, 'big', signed=True)
                elif isinstance(o, bytes):
                    script += len(o).to_bytes(1, 'big') + o
                else:
                    raise Exception()
                script += script.opcodes.OP_EQUALVERIFY.to_bytes(1, 'big')

        # make sure the stack depth is 0 and return true
        script += (
                script.opcodes.OP_DEPTH.to_bytes(1, 'big') +
                b'\x00' +
                script.opcodes.OP_EQUALVERIFY.to_bytes(1, 'big') +
                script.opcodes.OP_TRUE.to_bytes(1, 'big')
        )

        # run the script
        result = script.Script.process(b'', script, None, None)
        # check the output (None indicates expected failure)
        if output is None:
            self.assertFalse(result)
        else:
            self.assertTrue(result)


suite = unittest.TestLoader().loadTestsFromTestCase(TestScriptTransactions)
unittest.TextTestRunner(verbosity=2).run(suite)
