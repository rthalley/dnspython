import os.path
import sys
import unittest

if __name__ == '__main__':
    sys.path.insert(0, os.path.realpath('..'))
    if len(sys.argv) > 1:
        pattern = sys.argv[1]
    else:
        pattern = 'test*.py'
    suites = unittest.defaultTestLoader.discover('.', pattern)
    if not unittest.TextTestRunner(verbosity=2).run(suites).wasSuccessful():
        sys.exit(1)
