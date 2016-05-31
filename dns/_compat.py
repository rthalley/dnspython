import sys


if sys.version_info > (3,):
    long = int
    xrange = range
else:
    long = long
    xrange = xrange

# unicode / binary types
if sys.version_info > (3,):
    text_type = str
    binary_type = bytes
    string_types = (str,)
    unichr = chr
    def maybe_decode(x):
        return x.decode()
    def maybe_encode(x):
        return x.encode()
else:
    text_type = unicode
    binary_type = str
    string_types = (basestring,)
    unichr = unichr
    def maybe_decode(x):
        return x
    def maybe_encode(x):
        return x
