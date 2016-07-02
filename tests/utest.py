import os.path
import sys
try:
    import unittest2 as unittest
except ImportError:
    import unittest

if __name__ == '__main__':
    sys.path.insert(0, os.path.realpath('..'))
    suites = unittest.defaultTestLoader.discover('.')
    if not unittest.TextTestRunner(verbosity=2).run(suites).wasSuccessful():
        sys.exit(1)
