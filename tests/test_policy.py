"""Unit + property tests for the CIDR normalization core (stdlib only)."""

from __future__ import annotations

import ipaddress
import random

import pytest

from app.policy import (
    _normalize_family,
    allocate,
    AllocationImpossible,
    compare,
    evaluate,
    normalize,
    parse_address,
    parse_network,
    TRANSITION_KEYS,
)


def ref_subtract(allow, deny):
    """Reference implementation using ipaddress.address_exclude."""
    nets = list(ipaddress.collapse_addresses(allow))
    for d in ipaddress.collapse_addresses(deny):
        nxt = []
        for n in nets:
            if d == n or n.subnet_of(d):
                continue
            if d.subnet_of(n):
                nxt.extend(n.address_exclude(d))
            else:
                nxt.append(n)
        nets = nxt
    return set(ipaddress.collapse_addresses(nets))


def _strings(networks):
    return {str(n) for n in networks}


def test_simple_cut_through_ipv4():
    # 10.0.0.128/26 cuts 10.0.0.0/24 into two prefixes.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.192/26"]


def test_sibling_halves_merge_back():
    # Deny a hole whose leftovers are the two halves; they must merge.
    result = normalize(["10.0.0.0/24"], ["10.0.0.128/25"])
    assert result["ipv4"] == ["10.0.0.0/25"]


def test_nested_split_minimal():
    # Two adjacent /26 denies in the lower half leave one /25 survivor...
    result = normalize(
        ["10.0.0.0/24"],
        ["10.0.0.0/26", "10.0.0.64/26"],
    )
    assert result["ipv4"] == ["10.0.0.128/25"]


def test_non_sibling_adjacent_prefixes_do_not_merge():
    # 10.0.0.0/25 and 10.0.0.128/26 are adjacent but unequal siblings of no
    # common pair; minimal canonical remainder of /24 minus 10.0.0.192/26 is
    # exactly these two pieces (10.0.0.0/24 \\ 10.0.0.192/26).
    result = normalize(["10.0.0.0/24"], ["10.0.0.192/26"])
    assert result["ipv4"] == ["10.0.0.0/25", "10.0.0.128/26"]


def test_deny_swallows_allow_entirely():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/16"])
    assert result["ipv4"] == []


def test_deny_equals_allow():
    result = normalize(["10.0.0.0/24"], ["10.0.0.0/24"])
    assert result["ipv4"] == []


def test_overlapping_allow_inputs_are_collapsed():
    result = normalize(["10.0.0.0/25", "10.0.0.128/25"], [])
    assert result["ipv4"] == ["10.0.0.0/24"]


def test_duplicates_are_deduplicated():
    result = normalize(
        ["10.0.0.0/24", "10.0.0.0/24", "10.0.0.1/32"],
        ["10.0.0.0/8", "10.0.0.0/8"],
    )
    stats = result["stats"]
    assert stats["allow"] == {"input": 3, "unique": 2, "duplicates_removed": 1,
                              "ipv4": 2, "ipv6": 0}
    assert stats["deny"] == {"input": 2, "unique": 1, "duplicates_removed": 1,
                             "ipv4": 1, "ipv6": 0}
    assert stats["output"] == {"ipv4": 0, "ipv6": 0, "total": 0}


def test_mixed_families_are_independent():
    result = normalize(
        ["10.0.0.0/24", "2001:db8::/32"],
        ["10.0.0.128/25", "2001:db8:1::/48"],
    )
    assert result["ipv4"] == ["10.0.0.0/25"]
    assert result["ipv6"] == ["2001:db8::/48", "2001:db8:2::/47",
                              "2001:db8:4::/46", "2001:db8:8::/45",
                              "2001:db8:10::/44", "2001:db8:20::/43",
                              "2001:db8:40::/42", "2001:db8:80::/41",
                              "2001:db8:100::/40", "2001:db8:200::/39",
                              "2001:db8:400::/38", "2001:db8:800::/37",
                              "2001:db8:1000::/36", "2001:db8:2000::/35",
                              "2001:db8:4000::/34", "2001:db8:8000::/33"]


def test_sorting_is_stable_by_network_then_prefixlen():
    result = normalize(
        ["192.0.2.0/24", "10.0.0.0/8", "172.16.0.0/12"],
        [],
    )
    assert result["ipv4"] == ["10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24"]


def test_bare_address_means_host_prefix():
    result = normalize(["10.0.0.1", "::1"], [])
    assert result["ipv4"] == ["10.0.0.1/32"]
    assert result["ipv6"] == ["::1/128"]


def test_host_bits_rejected():
    with pytest.raises(ValueError):
        parse_network("10.0.0.1/24")
    with pytest.raises(ValueError):
        parse_network("2001:db8::1/32")


def test_garbage_rejected():
    for bad in ["not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", "", "10.0.0.0/"]:
        with pytest.raises(ValueError):
            parse_network(bad)


def test_host_prefix_subtraction():
    result = normalize(["10.0.0.0/30"], ["10.0.0.1/32", "10.0.0.2/32"])
    assert result["ipv4"] == ["10.0.0.0/32", "10.0.0.3/32"]


def test_output_is_non_overlapping_and_minimal():
    result = normalize(
        ["10.0.0.0/23", "10.0.2.0/24", "192.168.0.0/16"],
        ["10.0.1.0/24", "192.168.255.0/24", "10.0.0.128/25"],
    )
    nets = [ipaddress.ip_network(s) for s in result["ipv4"]]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)
    # No pair of complete sibling prefixes may remain (they would be merged).
    for i, a in enumerate(nets):
        if a.prefixlen == 0:
            continue
        supernet = a.supernet()
        siblings = [n for n in nets if n != a and n.subnet_of(supernet)
                    and n.prefixlen == a.prefixlen]
        # If both halves of the supernet are present, collapse would have
        # merged them, so at most a alone sits directly under that supernet.
        assert not (siblings and set(supernet.subnets()) <= set(nets))


@pytest.mark.parametrize("seed", range(64))
def test_matches_ipaddress_reference_ipv4(seed):
    rng = random.Random(seed)
    base = ipaddress.IPv4Address(0x0A000000)  # 10.0.0.0
    allow, deny = [], []
    for _ in range(rng.randint(1, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        allow.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))
    for _ in range(rng.randint(0, 12)):
        shift = rng.randint(0, 20)
        addr = int(base) + (rng.getrandbits(shift) << (24 - shift) if shift else 0)
        deny.append(ipaddress.IPv4Network((addr, rng.randint(8, 32)), strict=False))

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv4Network))
    assert actual == expected


@pytest.mark.parametrize("seed", range(32))
def test_matches_ipaddress_reference_ipv6(seed):
    rng = random.Random(1000 + seed)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_net():
        # Pick a host part within the 2001:db8::/32 block so the address can
        # never overflow 2**128, then mask it to the chosen prefix length.
        host = rng.randrange(2 ** 96)
        prefixlen = rng.randint(32, 120)
        addr = (base | host) & (~((1 << (128 - prefixlen)) - 1))
        return ipaddress.IPv6Network((addr, prefixlen), strict=False)

    allow = [random_net() for _ in range(rng.randint(1, 8))]
    deny = [random_net() for _ in range(rng.randint(0, 8))]

    expected = ref_subtract(allow, deny)
    actual = set(_normalize_family(allow, deny, ipaddress.IPv6Network))
    assert actual == expected


# --------------------------------------------------------------------------
# evaluate: longest-prefix matching
# --------------------------------------------------------------------------


def test_evaluate_longest_prefix_wins():
    # The more specific allow /25 must beat the broader allow /24.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/25"],
        [],
        ["10.0.0.1", "10.0.0.200"],
    )
    assert result == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/25",
         "matched_side": "allow"},
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_deny_beats_allow_at_equal_length():
    result = evaluate(
        ["10.0.0.0/24"],
        ["10.0.0.0/25"],
        ["10.0.0.1", "10.0.0.200"],
    )
    assert result[0] == {
        "decision": "deny", "matched_cidr": "10.0.0.0/25",
        "matched_side": "deny",
    }
    # Only the broader allow covers the upper half.
    assert result[1] == {
        "decision": "allow", "matched_cidr": "10.0.0.0/24",
        "matched_side": "allow",
    }


def test_evaluate_longer_prefix_always_wins_over_side():
    # Even though the /16 is deny, the longer allow /24 must win inside it.
    result = evaluate(
        ["10.0.0.0/24"],
        ["10.0.0.0/16"],
        ["10.0.0.1"],
    )
    assert result == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_stable_tie_break_keeps_first_list_entry():
    # Two identical allow entries: the earlier index wins; its canonical
    # representation is reported, which is the same string either way, so
    # also verify with two distinct equal-length matches is impossible
    # (a host belongs to only one network of a given prefix length); instead
    # assert the earlier duplicate does not produce a surprising result.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/24"],
        ["10.0.0.0/24"],
        ["10.0.0.1"],
    )
    assert result[0]["decision"] == "deny"
    assert result[0]["matched_cidr"] == "10.0.0.0/24"

    # Equal-length allow/allow duplicates remain stable allow decisions.
    result = evaluate(
        ["10.0.0.0/24", "10.0.0.0/24"], [], ["10.0.0.1"],
    )
    assert result[0] == {
        "decision": "allow", "matched_cidr": "10.0.0.0/24",
        "matched_side": "allow",
    }


def test_evaluate_unmatched_is_null():
    result = evaluate(["10.0.0.0/8"], ["10.1.0.0/16"], ["192.0.2.1"])
    assert result == [
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
    ]


def test_evaluate_order_is_preserved():
    addresses = ["10.0.0.2", "10.0.0.1", "10.1.0.1", "192.0.2.1"]
    result = evaluate(["10.0.0.0/24"], ["10.1.0.0/16"], addresses)
    assert [item["decision"] for item in result] == [
        "allow", "allow", "deny", "unmatched",
    ]
    assert [item["matched_cidr"] for item in result] == [
        "10.0.0.0/24", "10.0.0.0/24", "10.1.0.0/16", None,
    ]


def test_evaluate_mixed_families_are_independent():
    result = evaluate(
        ["10.0.0.0/8", "2001:db8::/32"],
        ["10.1.0.0/16", "2001:db8:1::/48"],
        ["10.1.0.1", "2001:db8:1::1", "2001:db8::1"],
    )
    assert result == [
        {"decision": "deny", "matched_cidr": "10.1.0.0/16",
         "matched_side": "deny"},
        {"decision": "deny", "matched_cidr": "2001:db8:1::/48",
         "matched_side": "deny"},
        {"decision": "allow", "matched_cidr": "2001:db8::/32",
         "matched_side": "allow"},
    ]


def test_evaluate_empty_inputs():
    assert evaluate([], [], ["10.0.0.1"]) == [
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
    ]
    assert evaluate([], [], []) == []


def test_evaluate_bare_host_prefix_cidr_entries_match():
    # A bare CIDR-list entry is a host prefix and matches that one address.
    result = evaluate(["10.0.0.1"], [], ["10.0.0.1", "10.0.0.2"])
    assert result[0] == {
        "decision": "allow", "matched_cidr": "10.0.0.1/32",
        "matched_side": "allow",
    }
    assert result[1]["decision"] == "unmatched"


def test_parse_address_rejects_cidr_and_garbage():
    assert parse_address("10.0.0.1") == ipaddress.IPv4Address("10.0.0.1")
    assert parse_address(" 2001:db8::1 ") == ipaddress.IPv6Address("2001:db8::1")
    for bad in ["10.0.0.1/24", "10.0.0.1/32", "bogus", "999.0.0.1", ""]:
        with pytest.raises(ValueError):
            parse_address(bad)
    with pytest.raises(ValueError):
        parse_address(10)


# --------------------------------------------------------------------------
# compare: scope partitioning and baseline/candidate diff
# --------------------------------------------------------------------------


def test_compare_basic_two_transitions():
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.128/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
         "candidate_decision": "deny"},
        {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
    ]
    assert result["transition_counts"] == {
        "allow->deny": "64",
        "allow->unmatched": "64",
        "deny->allow": "0",
        "deny->unmatched": "0",
        "unmatched->allow": "0",
        "unmatched->deny": "0",
    }


def test_compare_identical_policies_have_no_differences():
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/25"], ["10.0.0.128/26"],
        ["10.0.0.0/25"], ["10.0.0.128/26"],
    )
    assert result["differences"] == []
    assert all(value == "0" for value in result["transition_counts"].values())


def test_compare_sibling_regions_merge_recursively():
    # Candidate denies the whole upper /25 via two /26 halves; the two
    # equal-transition sibling halves must merge into one /25.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        [], ["10.0.0.128/26", "10.0.0.192/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]
    assert result["transition_counts"]["allow->deny"] == "128"
    assert result["transition_counts"]["allow->unmatched"] == "128"


def test_compare_deny_wins_equal_length_tie():
    # Equal /25 allow and deny in candidate: lower half denies; upper half,
    # covered by neither candidate entry, becomes unmatched.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.0/25"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
    ]


def test_compare_longer_prefix_beats_broader_side():
    result = compare(
        "10.0.0.0/24",
        [], [],
        ["10.0.0.0/24"], ["10.0.0.0/16"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.0/24", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]


def test_compare_adjacent_unequal_lengths_do_not_merge():
    # 128/26 allow->unmatched and 192/26 allow->deny are sibling /26s but
    # carry different transitions, so they must stay separate.
    result = compare(
        "10.0.0.0/24",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/25"], ["10.0.0.192/26"],
    )
    assert result["differences"] == [
        {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]


def test_compare_supernet_entry_outside_scope_still_applies():
    # Both sides share a broader allow; inside the narrower scope nothing
    # changes, even though the scope itself is not listed.
    result = compare(
        "10.0.0.0/25",
        ["10.0.0.0/24"], [],
        ["10.0.0.0/24"], [],
    )
    assert result["differences"] == []


def test_compare_other_family_entries_are_ignored():
    result = compare(
        "10.0.0.0/24",
        [], ["2001:db8::/32"],
        ["2001:db8::/32"], [],
    )
    assert result["differences"] == []


def test_compare_ipv6_scope_and_decimal_string_counts():
    result = compare(
        "2001:db8::/32",
        [], [],
        ["2001:db8::/32"], [],
    )
    assert result["differences"] == [
        {"cidr": "2001:db8::/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]
    # Count is a decimal string even at IPv6 magnitudes.
    assert result["transition_counts"]["unmatched->allow"] == str(2 ** 96)
    assert isinstance(result["transition_counts"]["unmatched->allow"], str)


def test_compare_host_prefix_scope():
    result = compare("10.0.0.5/32", [], [], ["10.0.0.5"], [])
    assert result["differences"] == [
        {"cidr": "10.0.0.5/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]


def test_compare_invalid_scope_raises():
    for bad in ["10.0.0.1/24", "bogus", "10.0.0.0/33", ""]:
        with pytest.raises(ValueError):
            compare(bad, [], [], [], [])


def _point_decisions(allow_raw, deny_raw, addresses):
    """evaluate() decisions for a list of bare addresses."""
    return [
        item["decision"]
        for item in evaluate(allow_raw, deny_raw, addresses)
    ]


def _assert_compare_exhaustive(scope, base_a, base_d, cand_a, cand_d):
    """Check compare() against per-address /evaluate over a small scope."""
    scope_net = ipaddress.ip_network(scope)

    result = compare(scope, base_a, base_d, cand_a, cand_d)
    blocks = [ipaddress.ip_network(d["cidr"]) for d in result["differences"]]

    # Enumerate every address of the scope (including network/broadcast,
    # which .hosts() omits for IPv4).
    start = int(scope_net.network_address)
    all_hosts = [
        ipaddress.ip_address(start + offset)
        for offset in range(scope_net.num_addresses)
    ]
    addresses = [str(host) for host in all_hosts]
    base_point = _point_decisions(base_a, base_d, addresses)
    cand_point = _point_decisions(cand_a, cand_d, addresses)

    # Output blocks are strict subnets of scope, non-overlapping, and carry a
    # genuine change.
    for diff, network in zip(result["differences"], blocks, strict=True):
        assert network.subnet_of(scope_net)
        assert diff["baseline_decision"] != diff["candidate_decision"]
    for i, left in enumerate(blocks):
        for right in blocks[i + 1:]:
            assert not left.overlaps(right)

    # Every differing address is covered by exactly one block; every address
    # covered by a block really does change, with the reported decisions.
    covered = [False] * len(addresses)
    for diff, network in zip(result["differences"], blocks, strict=True):
        for index, host in enumerate(all_hosts):
            if host in network:
                assert not covered[index]
                covered[index] = True
                assert base_point[index] == diff["baseline_decision"]
                assert cand_point[index] == diff["candidate_decision"]
    for index, changed in enumerate(
        b != c for b, c in zip(base_point, cand_point)
    ):
        assert covered[index] == changed

    # Totals match the per-address enumeration.
    totals = {key: 0 for key in TRANSITION_KEYS}
    for base, cand in zip(base_point, cand_point):
        if base != cand:
            totals[f"{base}->{cand}"] += 1
    assert {key: int(value) for key, value in
            result["transition_counts"].items()} == totals

    # Minimality: no output pair forms two complete siblings of one parent
    # with the same transition (those would have been merged).
    for diff, network in zip(result["differences"], blocks, strict=True):
        if network.prefixlen == 0:
            continue
        parent = network.supernet()
        same_label_siblings = [
            other for other_diff, other in zip(result["differences"], blocks)
            if other != network and other.subnet_of(parent)
            and other.prefixlen == network.prefixlen
            and (other_diff["baseline_decision"],
                 other_diff["candidate_decision"])
            == (diff["baseline_decision"], diff["candidate_decision"])
        ]
        assert not (
            len(same_label_siblings) == 1
            and set(parent.subnets()) <= set(blocks)
        )


@pytest.mark.parametrize("seed", range(40))
def test_compare_matches_pointwise_evaluation_ipv4(seed):
    rng = random.Random(2000 + seed)
    prefixlen = rng.randint(26, 29)  # <= /29 keeps enumeration cheap

    def random_list():
        items = []
        for _ in range(rng.randint(0, 5)):
            length = rng.randint(prefixlen - 2, 32)
            base = rng.randrange(2 ** 32)
            addr = (base >> (32 - length)) << (32 - length)
            items.append(str(ipaddress.IPv4Network((addr, length))))
        return items

    scope_addr = (rng.randrange(2 ** 32) >> (32 - prefixlen)) << (32 - prefixlen)
    scope = str(ipaddress.IPv4Network((scope_addr, prefixlen)))
    _assert_compare_exhaustive(
        scope, random_list(), random_list(), random_list(), random_list()
    )


@pytest.mark.parametrize("seed", range(16))
def test_compare_matches_pointwise_evaluation_ipv6(seed):
    rng = random.Random(3000 + seed)
    # Tiny /124-ish scopes under 2001:db8:: keep host enumeration cheap.
    prefixlen = rng.randint(122, 126)
    base = int(ipaddress.IPv6Address("2001:db8::"))

    def random_list():
        items = []
        for _ in range(rng.randint(0, 4)):
            length = rng.randint(prefixlen - 2, 128)
            host = rng.randrange(2 ** (128 - prefixlen))
            root = base + (host & ~((1 << (128 - prefixlen)) - 1))
            addr = (root >> (128 - length)) << (128 - length)
            items.append(str(ipaddress.IPv6Network((addr, length))))
        return items

    host = rng.randrange(2 ** (128 - prefixlen))
    scope_addr = (base + host) & ~((1 << (128 - prefixlen)) - 1)
    scope = str(ipaddress.IPv6Network((scope_addr, prefixlen)))
    _assert_compare_exhaustive(
        scope, random_list(), random_list(), random_list(), random_list()
    )


# --------------------------------------------------------------------------
# allocate: lexicographically-smallest complete subnet plan
# --------------------------------------------------------------------------


def test_allocate_lowest_aligned_subnets_without_occupied():
    result = allocate("10.0.0.0/24", [], [("a", 26), ("b", 26)])
    assert [item["cidr"] for item in result["allocations"]] == [
        "10.0.0.0/26", "10.0.0.64/26",
    ]
    assert result["remaining"] == ["10.0.0.128/25"]
    assert result["remaining_addresses"] == "128"


def test_allocate_remaining_includes_occupied_and_allocated_gaps():
    # scope /28 (16 addresses), occupy one /30 in the middle, allocate one
    # /31 at the front; the remainder is the minimal tiling of what is left.
    result = allocate(
        "10.0.0.0/28",
        ["10.0.0.8/30"],
        [("a", 31)],
    )
    assert [item["cidr"] for item in result["allocations"]] == ["10.0.0.0/31"]
    assert result["remaining"] == [
        "10.0.0.2/31", "10.0.0.4/30", "10.0.0.12/30",
    ]
    assert result["remaining_addresses"] == "10"
    assert not any(
        ipaddress.ip_network(left).overlaps(ipaddress.ip_network(right))
        for i, left in enumerate(result["remaining"])
        for right in result["remaining"][i + 1:]
    )


def test_allocate_no_requests_returns_scope_minus_occupied():
    result = allocate("10.0.0.0/24", ["10.0.0.128/26"], [])
    assert result["allocations"] == []
    assert result["remaining"] == ["10.0.0.0/25", "10.0.0.192/26"]
    assert result["remaining_addresses"] == "192"


def test_allocate_occupied_equal_to_scope_leaves_nothing():
    assert allocate("10.0.0.0/24", ["10.0.0.0/24"], []) == {
        "allocations": [],
        "remaining": [],
        "remaining_addresses": "0",
    }


def test_allocate_requires_backtracking():
    # Free: 10.0.0.0/25 + 10.0.0.128/26.  First-fit for the /26 request
    # would consume 10.0.0.0/26 and leave no /25; the search must undo it.
    result = allocate(
        "10.0.0.0/24",
        ["10.0.0.192/26"],
        [("small", 26), ("big", 25)],
    )
    assert [item["cidr"] for item in result["allocations"]] == [
        "10.0.0.128/26", "10.0.0.0/25",
    ]
    assert result["remaining"] == []
    assert result["remaining_addresses"] == "0"


def test_allocate_ipv6_decimal_totals():
    result = allocate("2001:db8::/120", [], [("x", 121), ("y", 122)])
    assert [item["cidr"] for item in result["allocations"]] == [
        "2001:db8::/121", "2001:db8::80/122",
    ]
    assert result["remaining"] == ["2001:db8::c0/122"]
    assert result["remaining_addresses"] == "64"


def test_allocate_impossible_raises():
    with pytest.raises(AllocationImpossible):
        allocate("10.0.0.0/25", [], [("a", 24)])
    with pytest.raises(AllocationImpossible):
        allocate("10.0.0.0/24", [], [("a", 24), ("b", 24)])
    with pytest.raises(AllocationImpossible):
        allocate(
            "10.0.0.0/24",
            ["10.0.0.0/24"],
            [("a", 32)],
        )


def _bruteforce_lex_min(scope, occupied, prefixes):
    """Reference lex-min allocation by exhaustive DFS, or None if infeasible.

    Enumerates every aligned subnet of each requested length inside scope
    and tries candidates in ascending network-address order, which is the
    same ordering the real search relies on.
    """
    scope_net = ipaddress.ip_network(scope)
    occupied_nets = [ipaddress.ip_network(c) for c in occupied]

    # Build the minimal free tiling by subtracting occupied one at a time via
    # the same address_exclude primitive the implementation uses.
    pieces = [scope_net]
    for blocked in occupied_nets:
        nxt = []
        for piece in pieces:
            if piece == blocked or piece.subnet_of(blocked):
                continue
            if blocked.subnet_of(piece):
                nxt.extend(piece.address_exclude(blocked))
            else:
                nxt.append(piece)
        pieces = list(ipaddress.collapse_addresses(nxt))

    def candidates(prefix_length):
        nets = []
        for piece in pieces:
            if piece.prefixlen <= prefix_length:
                nets.extend(piece.subnets(new_prefix=prefix_length))
        return sorted(set(nets), key=lambda n: (int(n.network_address), n.prefixlen))

    def search(index, used):
        if index == len(prefixes):
            return []
        for candidate in candidates(prefixes[index]):
            if any(candidate.overlaps(net) for net in used):
                continue
            rest = search(index + 1, used + [candidate])
            if rest is not None:
                return [candidate, *rest]
        return None

    return search(0, [])


def _subtract_all(scope, removed):
    """Minimal CIDR set of scope with every network in ``removed`` excluded."""
    pieces = {scope}
    for blocked in removed:
        nxt: set = set()
        for piece in pieces:
            if piece == blocked or piece.subnet_of(blocked):
                continue
            if blocked.subnet_of(piece):
                nxt.update(piece.address_exclude(blocked))
            else:
                nxt.add(piece)
        pieces = nxt
    return set(ipaddress.collapse_addresses(pieces))


@pytest.mark.parametrize("seed", range(120))
def test_allocate_matches_bruteforce_ipv4(seed):
    rng = random.Random(4000 + seed)
    scope_len = rng.randint(24, 28)
    scope = ipaddress.ip_network((
        (rng.randrange(2 ** scope_len)) << (32 - scope_len), scope_len
    ))

    # Choose pairwise non-overlapping occupied prefixes inside scope.
    occupied = []
    for _ in range(rng.randint(0, 4)):
        length = rng.randint(scope_len, min(scope_len + 4, 32))
        index = rng.randrange(2 ** (length - scope_len))
        net = list(scope.subnets(new_prefix=length))[index]
        if all(not net.overlaps(o) for o in occupied):
            occupied.append(net)

    count = rng.randint(0, 4)
    prefixes = [
        rng.randint(scope_len, min(scope_len + 5, 32)) for _ in range(count)
    ]

    expected = _bruteforce_lex_min(str(scope), [str(o) for o in occupied], prefixes)
    if expected is None:
        with pytest.raises(AllocationImpossible):
            allocate(
                str(scope),
                [str(o) for o in occupied],
                [(f"r{i}", p) for i, p in enumerate(prefixes)],
            )
        return

    result = allocate(
        str(scope),
        [str(o) for o in occupied],
        [(f"r{i}", p) for i, p in enumerate(prefixes)],
    )
    actual = [ipaddress.ip_network(item["cidr"]) for item in result["allocations"]]
    assert actual == expected

    # Allocations are aligned subnets of scope, pairwise disjoint and clear
    # of every occupied network.
    nets = occupied + actual
    for i, left in enumerate(nets):
        assert left.subnet_of(scope)
        for right in nets[i + 1:]:
            assert not left.overlaps(right)

    # Remaining is exactly scope minus occupied and allocations, minimal.
    free_ref = _subtract_all(scope, occupied + actual)
    assert set(map(ipaddress.ip_network, result["remaining"])) == free_ref
    assert result["remaining_addresses"] == str(
        sum(net.num_addresses for net in free_ref)
    )


@pytest.mark.parametrize("seed", range(40))
def test_allocate_matches_bruteforce_ipv6(seed):
    rng = random.Random(5000 + seed)
    base = int(ipaddress.IPv6Address("2001:db8::"))
    scope_len = rng.randint(122, 125)
    scope = ipaddress.IPv6Network((base, scope_len))

    occupied = []
    for _ in range(rng.randint(0, 3)):
        length = rng.randint(scope_len, min(scope_len + 3, 128))
        index = rng.randrange(2 ** (length - scope_len))
        net = list(scope.subnets(new_prefix=length))[index]
        if all(not net.overlaps(o) for o in occupied):
            occupied.append(net)

    prefixes = [
        rng.randint(scope_len, min(scope_len + 4, 128))
        for _ in range(rng.randint(0, 3))
    ]

    expected = _bruteforce_lex_min(str(scope), [str(o) for o in occupied], prefixes)
    if expected is None:
        with pytest.raises(AllocationImpossible):
            allocate(
                str(scope),
                [str(o) for o in occupied],
                [(f"r{i}", p) for i, p in enumerate(prefixes)],
            )
    else:
        result = allocate(
            str(scope),
            [str(o) for o in occupied],
            [(f"r{i}", p) for i, p in enumerate(prefixes)],
        )
        actual = [
            ipaddress.ip_network(item["cidr"]) for item in result["allocations"]
        ]
        assert actual == expected
        free_ref = _subtract_all(scope, occupied + actual)
        assert set(map(ipaddress.ip_network, result["remaining"])) == free_ref
        assert result["remaining_addresses"] == str(
            sum(net.num_addresses for net in free_ref)
        )
