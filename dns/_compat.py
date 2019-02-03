import sys

PY3 = sys.version_info[0] == 3
PY2 = sys.version_info[0] == 2


if PY3:
    long = int
    xrange = range
else:
    long = long  # pylint: disable=long-builtin
    xrange = xrange  # pylint: disable=xrange-builtin

# unicode / binary types
if PY3:
    text_type = str
    binary_type = bytes
    string_types = (str,)
else:
    text_type = unicode  # pylint: disable=unicode-builtin, undefined-variable
    binary_type = str
    string_types = (
        basestring,  # pylint: disable=basestring-builtin, undefined-variable
    )
