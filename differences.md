# Incompatible differences between dnspython 1.x and 2.x

## Rounding

dnspython 2.0 rounds in the standard python 3 fashion; dnspython 1.x rounded
in the python 2 style on both python 2 and 3.

# Removed hash module

dns.hash module was removed. Use Python built in hashlib instead.
