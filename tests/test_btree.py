import copy

import pytest

import dns.btree as btree


class BTreeDict(btree.BTreeDict):
    # We mostly test with an in-order optimized BTreeDict with t=3 as that's how we
    # generated the data.
    def __init__(self, *, t=3, original=None):
        super().__init__(t=t, original=original, in_order=True)


def add_keys(b, keys):
    if isinstance(keys, int):
        keys = range(keys)
    for key in keys:
        b[key] = True


def test_replace():
    N = 8
    b = BTreeDict()
    add_keys(b, N)
    b[0] = False
    b[5] = False
    b[7] = False
    for key in range(N):
        if key in {0, 5, 7}:
            assert b[key] == False
        else:
            assert b[key] == True


def test_min_max():
    N = 8
    b = BTreeDict()
    add_keys(b, N)
    assert b.root.minimum().key() == 0
    assert b.root.maximum().key() == N - 1
    del b[N - 1]
    del b[0]
    assert b.root.minimum().key() == 1
    assert b.root.maximum().key() == N - 2


def test_nonexistent():
    N = 8
    b = BTreeDict()
    add_keys(b, N)
    with pytest.raises(KeyError):
        b[1.5] == False
    assert b.delete_key(1.5) is None
    with pytest.raises(KeyError):
        del b[1.5]


def test_in_order():
    N = 100
    b = BTreeDict()
    add_keys(b, N)
    expected = list(range(N))
    assert list(b.keys()) == expected

    keys = list(range(N - 1, -1, -1))
    expected = N
    for key in keys:
        l = len(b)
        assert l == expected
        expected -= 1
        del b[key]
    assert len(b) == 0


# Some key orderings generated randomly but hardcoded here for test stability.
# The keys lead to 100% coverage in insert, find, and delete.

random_keys_1 = [
    36,
    14,
    89,
    67,
    80,
    98,
    71,
    29,
    92,
    91,
    79,
    49,
    63,
    74,
    19,
    4,
    23,
    60,
    10,
    31,
    94,
    46,
    18,
    84,
    61,
    42,
    77,
    54,
    76,
    38,
    26,
    37,
    24,
    99,
    45,
    7,
    97,
    32,
    53,
    96,
    82,
    52,
    8,
    58,
    11,
    3,
    15,
    47,
    17,
    21,
    28,
    2,
    20,
    12,
    95,
    44,
    16,
    9,
    51,
    30,
    33,
    34,
    88,
    55,
    43,
    72,
    57,
    66,
    22,
    56,
    68,
    87,
    73,
    6,
    25,
    59,
    0,
    75,
    90,
    78,
    50,
    13,
    83,
    93,
    39,
    81,
    41,
    70,
    48,
    35,
    65,
    64,
    62,
    5,
    27,
    86,
    40,
    1,
    85,
    69,
]

random_keys_2 = [
    49,
    28,
    0,
    19,
    14,
    76,
    65,
    8,
    12,
    90,
    71,
    36,
    31,
    24,
    83,
    59,
    98,
    48,
    26,
    82,
    46,
    84,
    80,
    33,
    74,
    75,
    60,
    99,
    20,
    61,
    88,
    81,
    41,
    58,
    85,
    54,
    96,
    23,
    72,
    66,
    1,
    37,
    57,
    64,
    27,
    13,
    40,
    73,
    69,
    32,
    55,
    34,
    5,
    2,
    39,
    9,
    93,
    50,
    47,
    92,
    79,
    78,
    63,
    10,
    30,
    77,
    87,
    53,
    7,
    56,
    21,
    18,
    62,
    6,
    11,
    95,
    70,
    44,
    42,
    97,
    35,
    91,
    43,
    16,
    89,
    45,
    67,
    4,
    22,
    17,
    25,
    51,
    94,
    52,
    68,
    3,
    15,
    86,
    38,
    29,
]


def test_random_trees():
    N = len(random_keys_1)
    b = BTreeDict()
    add_keys(b, random_keys_1)
    expected = list(range(N))
    assert list(b.keys()) == expected

    for key in random_keys_1:
        assert b[key]

    keys = random_keys_2
    expected_len = N
    for key in keys:
        l = len(b)
        assert l == expected_len
        expected_len -= 1
        del b[key]
    assert len(b) == 0


def test_random_trees_no_in_order_optimization():
    N = len(random_keys_1)
    b = btree.BTreeDict(t=3)
    add_keys(b, random_keys_1)
    expected = list(range(N))
    assert list(b.keys()) == expected

    for key in random_keys_1:
        assert b[key]

    keys = random_keys_2
    expected_len = N
    for key in keys:
        l = len(b)
        assert l == expected_len
        expected_len -= 1
        del b[key]
    assert len(b) == 0


def node_set(b):
    s = set()
    b._visit_preorder_by_node(lambda n: s.add(n))
    return s


def test_cow():
    N = len(random_keys_1)
    b = BTreeDict()
    add_keys(b, random_keys_1)
    expected = list(range(N))
    assert list(b.keys()) == expected
    nsb = node_set(b)

    with pytest.raises(ValueError):
        d = BTreeDict(original=b)
    b.make_immutable()
    with pytest.raises(btree.Immutable):
        b[100] = True
    with pytest.raises(btree.Immutable):
        del b[1]

    b2 = BTreeDict(original=b)
    keys = random_keys_2
    expected_len = N
    for key in keys:
        l = len(b2)
        assert l == expected_len
        expected_len -= 1
        del b2[key]
    assert len(b2) == 0
    b2[100] = True
    b2[101] = True
    assert list(b2.keys()) == [100, 101]

    # and b is unchanged
    assert list(b.keys()) == expected
    nsb2 = node_set(b)
    assert nsb == nsb2

    # copy should be the same as b
    b3 = copy.copy(b)
    assert list(b.keys()) == expected
    nsb3 = node_set(b3)
    assert nsb == nsb3


def test_cow_minimality():
    b = BTreeDict()
    add_keys(b, 8)
    b.make_immutable()
    b2 = BTreeDict(original=b)

    assert b.root is b2.root
    b2[7] = 100
    assert b.root is not b2.root
    assert b.root.children[0] is b2.root.children[0]
    assert b.root.children[1] is not b2.root.children[1]
    del b2[5]
    assert b.root is not b2.root
    assert b.root.children[0] is not b2.root.children[0]
    assert b.root.children[1] is not b2.root.children[1]


def test_cursor_seek():
    N = len(random_keys_1)
    b = BTreeDict()
    add_keys(b, random_keys_1)

    l = []
    c = b.cursor()
    while True:
        elt = c.next()
        if elt is None:
            break
        else:
            l.append(elt.key())
    expected = list(range(N))
    assert l == expected
    assert c.next() is None

    # same as previous but with explicit seek_first()
    l = []
    c = b.cursor()
    c.seek_first()
    while True:
        elt = c.next()
        if elt is None:
            break
        else:
            l.append(elt.key())
    expected = list(range(N))
    assert l == expected
    assert c.next() is None

    l = []
    c = b.cursor()
    c.seek_last()
    while True:
        elt = c.prev()
        if elt is None:
            break
        else:
            l.append(elt.key())
    expected = list(range(N - 1, -1, -1))
    assert l == expected
    assert c.prev() is None


def test_cursor_seek_before_and_after():
    N = 8
    b = BTreeDict()
    add_keys(b, N)

    c = b.cursor()

    # Seek before, leaf
    c.seek(2)
    assert c.next().key() == 2
    assert c.prev().key() == 2

    # Seek before, parent
    c.seek(5)
    assert c.next().key() == 5
    c.seek(5)
    assert c.prev().key() == 4

    # Seek after, leaf
    c.seek(2, False)
    assert c.next().key() == 3
    c.seek(2, False)
    assert c.prev().key() == 2

    # Seek after, leaf
    c.seek(2, False)
    assert c.next().key() == 3
    c.seek(2, False)
    assert c.prev().key() == 2

    # Seek after, parent
    c.seek(5, False)
    assert c.next().key() == 6
    c.seek(5, False)
    assert c.prev().key() == 5

    # Nonexistent
    c.seek(2.5)
    assert c.next().key() == 3
    c.seek(2.5)
    assert c.prev().key() == 2
    c.seek(4.5)
    assert c.next().key() == 5
    c.seek(5.5)
    assert c.prev().key() == 5


def test_cursor_reversing_in_parentnode():
    N = 11
    b = BTreeDict()
    add_keys(b, N)
    c = b.cursor()
    c.seek(5)
    assert c.next().key() == 5
    assert c.prev().key() == 5
    c.seek(5, False)
    assert c.prev().key() == 5
    assert c.next().key() == 5


def test_cursor_empty_tree_seeks():
    b = BTreeDict()
    c = b.cursor()
    c.seek(5)
    assert c.next() == None
    assert c.prev() == None


def test_parking():
    N = 11
    b = BTreeDict()
    add_keys(b, N)
    c = b.cursor()

    c.seek(5)
    assert c.next().key() == 5
    c.park()
    assert c.next().key() == 6

    c.seek(5)
    assert c.prev().key() == 4
    c.park()
    assert c.prev().key() == 3

    c.seek(5)
    assert c.next().key() == 5
    c.park()
    assert c.prev().key() == 5

    c.seek(5)
    assert c.prev().key() == 4
    c.park()
    assert c.next().key() == 4

    expected = list(range(11))

    c.seek_first()
    got = []
    while True:
        e = c.next()
        if e is None:
            break
        got.append(e.key())
        c.park()
    assert got == expected

    c.seek_last()
    got = []
    while True:
        e = c.prev()
        if e is None:
            break
        got.append(e.key())
        c.park()
    assert got == list(reversed(expected))

    # parking on the boundary

    c.seek_first()
    c.park()
    assert c.next().key() == 0

    c.seek_last()
    c.park()
    assert c.prev().key() == 10

    c.seek(0)
    c.park()
    assert c.next().key() == 0

    c.seek(10, False)
    c.park()
    assert c.prev().key() == 10

    # double parking (parking idempotency)

    c.seek_first()
    c.park()
    c.park()
    assert c.next().key() == 0

    # mutation

    c.seek(5)
    c.park()
    b[4.5] = True
    assert c.next().key() == 5

    c.seek(5)
    c.park()
    b[5.5] = True
    assert c.next().key() == 5

    c.seek(5)
    c.park()
    del b[5]
    assert c.next().key() == 5.5

    c.seek(5)
    c.park()
    b[4.49] = True
    b[4.51] = True
    assert c.prev().key() == 4.51

    c.seek(5)
    c.park()
    b[5.49] = True
    b[5.51] = True
    assert c.next().key() == 5.49


def test_automatic_parking():
    N = 11
    b = BTreeDict()
    add_keys(b, N)

    with b.cursor() as c:
        assert c in b.cursors
        c.seek(5)
        assert c.next().key() == 5
        b[5.5] = True
        assert c.next().key() == 5.5
    assert len(b.cursors) == 0


def test_visit_in_order():
    N = 100
    b = BTreeDict()
    add_keys(b, N)

    l = []
    b.visit_in_order(lambda elt: l.append(elt.key()))
    assert l == list(range(N))


def test_visit_preorder_by_node():
    N = 100
    b = BTreeDict()
    add_keys(b, N)

    kl = []
    b._visit_preorder_by_node(lambda node: kl.append([elt.key() for elt in node.elts]))
    expected = [
        [35, 71],
        [5, 11, 17, 23, 29],
        [0, 1, 2, 3, 4],
        [6, 7, 8, 9, 10],
        [12, 13, 14, 15, 16],
        [18, 19, 20, 21, 22],
        [24, 25, 26, 27, 28],
        [30, 31, 32, 33, 34],
        [41, 47, 53, 59, 65],
        [36, 37, 38, 39, 40],
        [42, 43, 44, 45, 46],
        [48, 49, 50, 51, 52],
        [54, 55, 56, 57, 58],
        [60, 61, 62, 63, 64],
        [66, 67, 68, 69, 70],
        [77, 83, 89, 95],
        [72, 73, 74, 75, 76],
        [78, 79, 80, 81, 82],
        [84, 85, 86, 87, 88],
        [90, 91, 92, 93, 94],
        [96, 97, 98, 99],
    ]
    assert kl == expected


def test_exact_delete():
    N = 8
    b = BTreeDict()
    add_keys(b, N)
    for key in [5, 0, 7]:
        elt = b.get_element(key)
        assert elt is not None
        bogus_elt = btree.KV(key, False)
        with pytest.raises(ValueError):
            b.delete_exact(bogus_elt)
        b.delete_exact(elt)
        with pytest.raises(ValueError):
            b.delete_exact(elt)


def test_find_nonexistent_node():
    # This is just for 100% coverage
    b = BTreeDict()
    b[0] = True
    assert b.root._get_node(0) == (b.root, 0)
    assert b.root._get_node(1) == (None, 0)


def test_t_too_small():
    with pytest.raises(ValueError):
        BTreeDict(t=2)


def test_immutable_idempotent():
    # Again just for coverage.
    b = BTreeDict()
    b.make_immutable()
    assert b._immutable
    b.make_immutable()
    assert b._immutable


def test_btree_set():
    b: btree.BTreeSet[int] = btree.BTreeSet()
    b.add(1)
    assert 1 in b
    b.add(2)
    assert 1 in b
    assert 2 in b
    assert len(b) == 2
    assert list(b) == [1, 2]
    b.discard(1)
    assert 1 not in b
    assert 2 in b
    assert len(b) == 1
    assert list(b) == [2]
    b.discard(1)
    assert 1 not in b
    assert 2 in b
    assert len(b) == 1
    b.discard(2)
    assert 1 not in b
    assert 2 not in b
    assert len(b) == 0
    assert list(b) == []
