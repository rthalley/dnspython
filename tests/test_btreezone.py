from typing import cast

import dns.btreezone
import dns.rdataset
import dns.zone

Node = dns.btreezone.Node

simple_zone = """
$ORIGIN example.
$TTL 300
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
ns1 a 10.0.0.1
ns2 a 10.0.0.2
sub ns ns1.sub
sub ns ns2.sub
ns1.sub a 10.0.0.3
ns2.sub a 10.0.0.4
ns1.sub2 a 10.0.0.5
ns2.sub2 a 10.0.0.6
text txt "here to be after sub2"
"""


def make_example(text: str, relativize: bool = False) -> dns.btreezone.Zone:
    z = dns.zone.from_text(
        simple_zone, "example.", relativize=relativize, zone_factory=dns.btreezone.Zone
    )
    return cast(dns.btreezone.Zone, z)


def do_test_node_flags(relativize: bool):
    z = make_example(simple_zone, relativize)
    n = cast(Node, z.get_node("@"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert n.is_origin()
    assert n.is_origin_or_glue()
    assert n.is_immutable()
    n = cast(Node, z.get_node("sub"))
    assert n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()
    n = cast(Node, z.get_node("ns1.sub"))
    assert not n.is_delegation()
    assert n.is_glue()
    assert not n.is_origin()
    assert n.is_origin_or_glue()


def test_node_flags_absolute():
    do_test_node_flags(False)


def test_node_flags_relative():
    do_test_node_flags(True)


def test_flags_in_constructor():
    n = Node()
    assert n.flags == 0
    n = Node(dns.btreezone.NodeFlags.ORIGIN)
    assert n.is_origin()


def do_test_obscure_and_expose(relativize: bool):
    z = make_example(simple_zone, relativize=relativize)
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()
    rds = dns.rdataset.from_text("in", "ns", 300, "ns1.sub2", "ns2.sub2")
    with z.writer() as txn:
        txn.replace("sub2", rds)
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert n.is_glue()
    assert not n.is_origin()
    assert n.is_origin_or_glue()
    with z.writer() as txn:
        txn.delete("sub2")
        txn.delete("ns2.sub2")  # for other coverage purposes!
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()
    # repeat but delete just the rdataset
    rds = dns.rdataset.from_text("in", "ns", 300, "ns1.sub2", "ns2.sub2")
    with z.writer() as txn:
        txn.replace("sub2", rds)
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert n.is_glue()
    assert not n.is_origin()
    assert n.is_origin_or_glue()
    with z.writer() as txn:
        txn.delete("sub2", "NS")
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()


def test_obscure_and_expose_absolute():
    do_test_obscure_and_expose(False)


def test_obscure_and_expose_relative():
    do_test_obscure_and_expose(True)
