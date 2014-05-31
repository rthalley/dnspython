import os.path
import sys
import unittest

if __name__ == '__main__':
    sys.path.insert(0, os.path.realpath('..'))
    suites = unittest.defaultTestLoader.discover('.')
    unittest.TextTestRunner(verbosity=2).run(suites)
