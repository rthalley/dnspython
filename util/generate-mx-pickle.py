import pickle
import sys

import dns.rdata
import dns.version

# Generate a pickled mx RR for the current dnspython version

mx = dns.rdata.from_text("in", "mx", "10 mx.example.")
filename = f"pickled-{dns.version.MAJOR}-{dns.version.MINOR}.pickle"
with open(filename, "wb") as f:
    pickle.dump(mx, f)
with open(filename, "rb") as f:
    mx2 = pickle.load(f)
if mx == mx2:
    print("ok")
else:
    print("DIFFERENT!")
    sys.exit(1)
