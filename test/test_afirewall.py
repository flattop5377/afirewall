from afirewall import afirewall
import os
import unittest

class TestAfirewall(unittest.TestCase):
    def testConfigFileReadable(self):
        parser = afirewall.get_parser()
        args = parser.parse_args(['test', '-c', 'afirewall.conf'])
        self.assertTrue(os.access(args.config, mode=os.R_OK))

if __name__ == '__main__':
    unittest.main()
