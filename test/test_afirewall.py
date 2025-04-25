from afirewall import afirewall
import os
import unittest

class TestAfirewall(unittest.TestCase):
    def testConfigFileReadable(self):
        parser = afirewall.get_parser()
        args = parser.parse_args(['test', '-b=.'])
        self.assertTrue(os.access(args.basedir + '/afirewall.conf', mode=os.R_OK))

if __name__ == '__main__':
    unittest.main()
