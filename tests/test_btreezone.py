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
a txt "a"
c.b.a txt "cba"
b txt "b"
sub ns ns1.sub
sub ns ns2.sub
ns1.sub a 10.0.0.3
ns2.sub a 10.0.0.4
ns1.sub2 a 10.0.0.5
ns2.sub2 a 10.0.0.6
text txt "here to be after sub2"
z txt "z"
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
    sub2_name = z._validate_name("sub2")
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        assert sub2_name not in version.delegations
    rds = dns.rdataset.from_text("in", "ns", 300, "ns1.sub2", "ns2.sub2")
    with z.writer() as txn:
        txn.replace("sub2", rds)
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        assert sub2_name in version.delegations
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert n.is_glue()
    assert not n.is_origin()
    assert n.is_origin_or_glue()
    with z.writer() as txn:
        txn.delete("sub2")
        txn.delete("ns2.sub2")  # for other coverage purposes!
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        assert sub2_name not in version.delegations
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()
    # repeat but delete just the rdataset
    rds = dns.rdataset.from_text("in", "ns", 300, "ns1.sub2", "ns2.sub2")
    with z.writer() as txn:
        txn.replace("sub2", rds)
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        assert sub2_name in version.delegations
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert n.is_glue()
    assert not n.is_origin()
    assert n.is_origin_or_glue()
    with z.writer() as txn:
        txn.delete("sub2", "NS")
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        assert sub2_name not in version.delegations
    n = cast(Node, z.get_node("ns1.sub2"))
    assert not n.is_delegation()
    assert not n.is_glue()
    assert not n.is_origin()
    assert not n.is_origin_or_glue()


def test_obscure_and_expose_absolute():
    do_test_obscure_and_expose(False)


def test_obscure_and_expose_relative():
    do_test_obscure_and_expose(True)


def do_test_delegations(relativize: bool):
    z = make_example(simple_zone, relativize=relativize)
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        name = z._validate_name("a.b.c.sub.example.")
        delegation, is_glue = version.delegations.get_delegation(name)
        assert delegation == z._validate_name("sub.example.")
        assert is_glue
        assert version.delegations.is_glue(name)
        name = z._validate_name("sub.example.")
        delegation, is_glue = version.delegations.get_delegation(name)
        assert delegation == z._validate_name("sub.example.")
        assert not is_glue
        assert not version.delegations.is_glue(name)
        name = z._validate_name("text.example.")
        delegation, is_glue = version.delegations.get_delegation(name)
        assert delegation is None
        assert not is_glue
        assert not version.delegations.is_glue(name)


def test_delegations_absolute():
    do_test_delegations(False)


def test_delegations_relative():
    do_test_delegations(True)


def do_test_bounds(relativize: bool):
    z = make_example(simple_zone, relativize=relativize)
    with z.reader() as txn:
        version = cast(dns.btreezone.ImmutableVersion, txn.version)
        # tuple is (name, left, right, closest, is_equal, is_delegation)
        tests = [
            ("example.", "example.", "a.example.", "example.", True, False),
            ("a.z.example.", "z.example.", None, "z.example.", False, False),
            (
                "a.b.a.example.",
                "a.example.",
                "c.b.a.example.",
                "b.a.example.",
                False,
                False,
            ),
            (
                "d.b.a.example.",
                "c.b.a.example.",
                "b.example.",
                "b.a.example.",
                False,
                False,
            ),
            (
                "d.c.b.a.example.",
                "c.b.a.example.",
                "b.example.",
                "c.b.a.example.",
                False,
                False,
            ),
            (
                "sub.example.",
                "sub.example.",
                "ns1.sub2.example.",
                "sub.example.",
                True,
                True,
            ),
            (
                "ns1.sub.example.",
                "sub.example.",
                "ns1.sub2.example.",
                "sub.example.",
                False,
                True,
            ),
        ]
        for name, left, right, closest, is_equal, is_delegation in tests:
            name = z._validate_name(name)
            left = z._validate_name(left)
            if right is not None:
                right = z._validate_name(right)
            closest = z._validate_name(closest)
            bounds = version.bounds(name)
            print(bounds)
            assert bounds.left == left
            assert bounds.right == right
            assert bounds.closest_encloser == closest
            assert bounds.is_equal == is_equal
            assert bounds.is_delegation == is_delegation


def test_bounds_absolute():
    do_test_bounds(False)


def test_bounds_relative():
    do_test_bounds(True)
