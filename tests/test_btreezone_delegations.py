from typing import cast

import pytest

import dns.btreezone
import dns.rdataset
import dns.zone

FLAGS = dns.btreezone.NodeFlags
NS = dns.rdataset.from_text("IN", "NS", 300, "ns.example.")
A = dns.rdataset.from_text("IN", "A", 300, "192.0.2.1")
TXT = dns.rdataset.from_text("IN", "TXT", 300, '"present"')
CNAME = dns.rdataset.from_text("IN", "CNAME", 300, "target.example.")


def make_zone(relativize):
    return cast(
        dns.btreezone.Zone,
        dns.zone.from_text(
            "@ 300 SOA ns.example. hostmaster.example. 1 2 3 4 5\n"
            "@ 300 NS ns.example.\n",
            "example.",
            relativize=relativize,
            zone_factory=dns.btreezone.Zone,
        ),
    )


def assert_state(txn, cuts, flags, query_cut):
    zone = txn.zone
    version = cast(dns.btreezone.ImmutableVersion, txn.version)
    assert set(version.delegations) == {zone._validate_name(name) for name in cuts}
    for name, expected in flags.items():
        node = cast(dns.btreezone.Node, txn.get_node(zone._validate_name(name)))
        assert node.flags == expected
    bounds = version.bounds("host.deep.grand.child")
    assert bounds.is_delegation == (query_cut is not None)
    if query_cut is not None:
        assert bounds.left == zone._validate_name(query_cut)
        assert bounds.closest_encloser == zone._validate_name(query_cut)


@pytest.mark.parametrize("relativize", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_nested_delegations_independent_of_load_order(relativize, reverse):
    zone = make_zone(relativize)
    names = ["child", "grand.child", "deep.grand.child"]
    if reverse:
        names.reverse()
    with zone.writer() as txn:
        for name in names:
            txn.add(name, NS)
        txn.add("host.deep.grand.child", A)
    with zone.reader() as txn:
        assert_state(
            txn,
            ["child"],
            {
                "child": FLAGS.DELEGATION,
                "grand.child": FLAGS.GLUE,
                "deep.grand.child": FLAGS.GLUE,
                "host.deep.grand.child": FLAGS.GLUE,
            },
            "child",
        )


@pytest.mark.parametrize("relativize", [False, True])
@pytest.mark.parametrize("delete_node", [False, True])
def test_nested_delegations_exposed_with_snapshot_and_rollback(relativize, delete_node):
    zone = make_zone(relativize)
    with zone.writer() as txn:
        txn.add("grand.child", NS)
        txn.add("deep.grand.child", NS)
        txn.add("host.deep.grand.child", A)
    exposed = {
        "grand.child": FLAGS.DELEGATION,
        "deep.grand.child": FLAGS.GLUE,
        "host.deep.grand.child": FLAGS.GLUE,
    }
    with zone.reader() as original:
        # A rolled-back ancestor insertion must not mutate the committed nodes
        # or delegation index shared with a reader.
        with pytest.raises(RuntimeError, match="rollback"):
            with zone.writer() as txn:
                txn.add("child", NS)
                raise RuntimeError("rollback")
        assert_state(original, ["grand.child"], exposed, "grand.child")
        with zone.reader() as current:
            assert_state(current, ["grand.child"], exposed, "grand.child")
        with zone.writer() as txn:
            txn.add("child", NS)
        assert_state(original, ["grand.child"], exposed, "grand.child")
    hidden = {name: FLAGS.GLUE for name in exposed}
    hidden["child"] = FLAGS.DELEGATION
    with zone.reader() as previous:
        assert_state(previous, ["child"], hidden, "child")
        with pytest.raises(RuntimeError, match="rollback"):
            with zone.writer() as txn:
                txn.delete("child")
                raise RuntimeError("rollback")
        with zone.reader() as current:
            assert_state(current, ["child"], hidden, "child")
        with zone.writer() as txn:
            if delete_node:
                txn.delete("child")
            else:
                txn.delete("child", "NS")
        assert_state(previous, ["child"], hidden, "child")
        with zone.reader() as current:
            assert_state(current, ["grand.child"], exposed, "grand.child")
        with zone.writer() as txn:
            txn.delete("grand.child", "NS")
        with zone.reader() as current:
            assert_state(
                current,
                ["deep.grand.child"],
                {
                    "deep.grand.child": FLAGS.DELEGATION,
                    "host.deep.grand.child": FLAGS.GLUE,
                },
                "deep.grand.child",
            )


@pytest.mark.parametrize("relativize", [False, True])
def test_delegation_survives_copy_on_write_and_implicit_ns_removal(relativize):
    zone = make_zone(relativize)
    with zone.writer() as txn:
        txn.add("child", NS)
        txn.add("grand.child", NS)
        txn.add("deep.grand.child", TXT)
        txn.add("host.deep.grand.child", A)
    hidden = {
        "child": FLAGS.DELEGATION,
        "grand.child": FLAGS.GLUE,
        "deep.grand.child": FLAGS.GLUE,
        "host.deep.grand.child": FLAGS.GLUE,
    }
    with zone.reader() as original:
        with zone.writer() as txn:
            txn.add("child", TXT)
        with zone.reader() as current:
            assert_state(current, ["child"], hidden, "child")
        with zone.writer() as txn:
            # Replacing regular data with a CNAME removes the NS rdataset too.
            txn.replace("child", CNAME)
        assert_state(original, ["child"], hidden, "child")
    with zone.reader() as current:
        assert current.get("child", "NS") is None
        assert current.get("child", "CNAME") == CNAME
        assert_state(
            current,
            ["grand.child"],
            {
                "child": FLAGS(0),
                "grand.child": FLAGS.DELEGATION,
                "deep.grand.child": FLAGS.GLUE,
                "host.deep.grand.child": FLAGS.GLUE,
            },
            "grand.child",
        )


@pytest.mark.parametrize("relativize", [False, True])
def test_exposed_sibling_delegations_and_removed_glue_ns(relativize):
    zone = make_zone(relativize)
    with zone.writer() as txn:
        txn.add("child", NS)
        txn.add("grand.child", NS)
        txn.add("deep.grand.child", NS)
        txn.add("host.deep.grand.child", A)
        txn.add("plain.child", TXT)
        txn.add("sibling.child", NS)
        txn.add("host.sibling.child", A)
        txn.add("removed.child", NS)
        txn.add("removed.child", TXT)
    with zone.writer() as txn:
        txn.delete("removed.child", "NS")
        txn.delete("child")
    with zone.reader() as current:
        assert_state(
            current,
            ["grand.child", "sibling.child"],
            {
                "grand.child": FLAGS.DELEGATION,
                "deep.grand.child": FLAGS.GLUE,
                "host.deep.grand.child": FLAGS.GLUE,
                "plain.child": FLAGS(0),
                "sibling.child": FLAGS.DELEGATION,
                "host.sibling.child": FLAGS.GLUE,
                "removed.child": FLAGS(0),
            },
            "grand.child",
        )


@pytest.mark.parametrize("relativize", [False, True])
def test_origin_learned_from_zone_file_is_not_a_delegation(relativize):
    zone = cast(
        dns.btreezone.Zone,
        dns.zone.from_text(
            "$ORIGIN example.\n"
            "@ 300 SOA ns hostmaster 1 2 3 4 5\n"
            "@ 300 NS ns\n"
            "child 300 NS ns.child\n",
            relativize=relativize,
            zone_factory=dns.btreezone.Zone,
        ),
    )
    with zone.reader() as current:
        assert_state(
            current,
            ["child"],
            {"@": FLAGS.ORIGIN, "child": FLAGS.DELEGATION},
            "child",
        )
