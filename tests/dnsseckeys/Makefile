all:
	dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com
	dnssec-keygen -a ECDSAP256SHA256  -n ZONE example.com
	dnssec-keygen -a ECDSAP384SHA384  -n ZONE example.com
	dnssec-keygen -a ED25519 -n ZONE example.com
	dnssec-keygen -a ED448 -n ZONE example.com
