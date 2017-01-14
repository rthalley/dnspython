#!/usr/bin/env python3

import importlib
import sys

name = sys.argv[1]
title = sys.argv[2]

print(title)
print('=' * len(title))
print()

module = importlib.import_module(name)
for t in sorted(module._by_text.keys()):
    print('.. py:data:: {}.{}'.format(name, t))
    print('   :annotation: = {}'.format(module._by_text[t]))
