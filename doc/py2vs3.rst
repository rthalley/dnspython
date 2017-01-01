Python 2 vs. Python 3
---------------------

Dnspython was originally written in Python 2, and for some years had a
separate Python 3 branch.  Thanks to some excellent work by
contributors to the project, there is now a single source tree that
works for both.

The most significant user-visible differences between the two are in
the representations of binary data and textual data.  For Python 3,
binary data is stored using the `bytes` type, and textual data is stored
using the `str` type.  For Python 2, binary data is stored using the
`str` type, and textual data can use the `str` or `unicode` types.
Because there is a single source tree, the documentation will refer to
`binary` and `text` when describing the types of binary data or
textual data, respectively.


