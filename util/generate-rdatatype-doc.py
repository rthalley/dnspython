import dns.rdatatype

print("Rdatatypes")
print("----------")
print()
by_name = {}
for rdtype in dns.rdatatype.RdataType:
    short_name = dns.rdatatype.to_text(rdtype).replace("-", "_")
    by_name[short_name] = int(rdtype)
for k in sorted(by_name.keys()):
    v = by_name[k]
    print(f".. py:data:: dns.rdatatype.{k}")
    print(f"   :annotation: = {v}")
