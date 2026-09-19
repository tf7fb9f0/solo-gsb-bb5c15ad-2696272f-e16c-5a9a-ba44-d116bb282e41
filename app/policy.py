"""CIDR allow/deny normalization built on the standard-library ``ipaddress``.

The core operation is a set difference ``allow - deny`` computed independently
for IPv4 and IPv6.  When a deny prefix cuts through an allow prefix the allow
network is recursively split into its two halves until every deny boundary is
aligned with a prefix.  Pieces are merged back only when they form two
complete, adjacent sibling prefixes (via :func:`ipaddress.collapse_addresses`),
which yields the equivalent, non-overlapping and minimum-cardinality CIDR set.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import TypeAlias, Union

Network: TypeAlias = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
Address: TypeAlias = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Side rank used as the second component of the match-comparison key: at equal
# prefix length a deny entry must beat an allow entry.
_SIDE_RANK: dict[str, int] = {"allow": 0, "deny": 1}

_MAX_PREFIXLEN: dict[type, int] = {
    ipaddress.IPv4Network: 32,
    ipaddress.IPv6Network: 128,
}


def parse_network(value: object) -> Network:
    """Parse a strict CIDR string into an IPv4/IPv6 network object.

    ``strict=True`` rejects addresses with host bits set (e.g. ``10.0.0.1/24``).
    A bare address (``10.0.0.1``) is accepted as a host prefix (``/32`` or
    ``/128``).  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"CIDR must be a string, got {type(value).__name__}")
    return ipaddress.ip_network(value.strip(), strict=True)


def parse_address(value: object) -> Address:
    """Parse a bare IPv4/IPv6 address (CIDR notation is rejected).

    Unlike :func:`parse_network`, neither ``10.0.0.1/24`` nor a host prefix
    such as ``10.0.0.1/32`` is accepted here — evaluation targets are plain
    addresses only.  Any invalid input raises :class:`ValueError`.
    """
    if not isinstance(value, str):
        raise ValueError(f"address must be a string, got {type(value).__name__}")
    text = value.strip()
    if "/" in text:
        raise ValueError(f"{value!r} is an address with a prefix length")
    return ipaddress.ip_address(text)


def _sort_key(network: Network) -> tuple[bytes, int]:
    # ``packed`` orders network addresses as unsigned byte strings (works for
    # both families); prefix length is the secondary, stable key.
    return network.network_address.packed, network.prefixlen


def _diff(network: Network, deny: Sequence[Network]) -> list[Network]:
    """Subtract every deny network from one allow network by recursive splits.

    Caller guarantees that ``deny`` contains only strict subnets of
    ``network`` (equal/net-supernet cases are handled before calling this).
    Each recursion splits ``network`` into its two immediate sibling halves;
    a half that contains no deny prefix survives whole, while a half that does
    is split again — this is exactly the "cut through, split recursively"
    rule, and it produces maximal (minimum-count) aligned prefixes.
    """
    if not deny:
        return [network]

    # Defensive guard: a /32 or /128 has no strict subnets, so with a
    # correctly filtered ``deny`` this branch is unreachable.
    if network.prefixlen == _MAX_PREFIXLEN[type(network)]:
        return [network]

    left, right = network.subnets()

    result: list[Network] = []
    for half in (left, right):
        half_deny = [d for d in deny if d.subnet_of(half)]
        if any(d == half for d in half_deny):
            # The whole half is denied: it contributes nothing.
            continue
        if not half_deny:
            # No deny boundary touches the half: keep it whole.
            result.append(half)
        else:
            # Deny prefixes cut through the half: split again.
            result.extend(_diff(half, half_deny))
    return result


def _normalize_family(
    allow: Iterable[Network],
    deny: Iterable[Network],
    family: type,
) -> list[Network]:
    """Compute allow - deny for one address family, minimum and non-overlapping."""
    # Collapsing first removes duplicates/overlap and contained prefixes in
    # each input list, which also bounds the recursion work below.
    allow_nets = list(ipaddress.collapse_addresses(
        n for n in allow if isinstance(n, family)
    ))
    deny_nets = list(ipaddress.collapse_addresses(
        n for n in deny if isinstance(n, family)
    ))

    survivors: list[Network] = []
    for network in allow_nets:
        strict_deny: list[Network] = []
        swallowed = False
        for blocked in deny_nets:
            if network == blocked or network.subnet_of(blocked):
                # A deny prefix equal to or larger than the allow network
                # removes it completely.
                swallowed = True
                break
            if blocked.subnet_of(network):
                # A deny prefix cutting through the network: recurse.
                strict_deny.append(blocked)
        if swallowed:
            continue
        if not strict_deny:
            survivors.append(network)
        else:
            survivors.extend(_diff(network, strict_deny))

    # Sibling-only merge.  collapse_addresses merges a pair only when both are
    # complete adjacent halves of one common parent; merely adjacent prefixes
    # of unequal length are left untouched.
    merged = list(ipaddress.collapse_addresses(survivors))
    merged.sort(key=_sort_key)
    return merged


def _list_stats(raw: Sequence[str], networks: Sequence[Network]) -> dict:
    unique = set(networks)
    return {
        "input": len(raw),
        "unique": len(unique),
        "duplicates_removed": len(raw) - len(unique),
        "ipv4": sum(isinstance(n, ipaddress.IPv4Network) for n in unique),
        "ipv6": sum(isinstance(n, ipaddress.IPv6Network) for n in unique),
    }


def normalize(allow_raw: Sequence[str], deny_raw: Sequence[str]) -> dict:
    """Parse, validate and normalize allow/deny CIDR lists.

    Input strings are assumed to have been validated already (e.g. by the
    Pydantic schema); a malformed value raises :class:`ValueError`.
    """
    allow_nets = [parse_network(item) for item in allow_raw]
    deny_nets = [parse_network(item) for item in deny_raw]

    ipv4_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv4Network
    )
    ipv6_result = _normalize_family(
        allow_nets, deny_nets, ipaddress.IPv6Network
    )

    return {
        "ipv4": [str(network) for network in ipv4_result],
        "ipv6": [str(network) for network in ipv6_result],
        "stats": {
            "allow": _list_stats(allow_raw, allow_nets),
            "deny": _list_stats(deny_raw, deny_nets),
            "output": {
                "ipv4": len(ipv4_result),
                "ipv6": len(ipv6_result),
                "total": len(ipv4_result) + len(ipv6_result),
            },
        },
    }


def _best_match(
    address: Address,
    entries: Sequence[tuple[int, Network, str]],
) -> dict | None:
    """Return the winning list entry for one address, or ``None`` if none match.

    ``entries`` holds ``(original_index, network, side)`` triples restricted to
    the address family.  The comparison key orders by:

    1. prefix length — longest-prefix wins;
    2. side rank — at equal length ``deny`` beats ``allow``;
    3. original list index (negated) — the earlier entry in its side list
       wins, which makes the final decision stable.
    """
    best: tuple[int, int, int] | None = None
    best_network: Network | None = None
    best_side: str | None = None
    for index, network, side in entries:
        if address in network:
            key = (network.prefixlen, _SIDE_RANK[side], -index)
            if best is None or key > best:
                best = key
                best_network = network
                best_side = side
    if best is None:
        return None
    return {
        "decision": best_side,
        "matched_cidr": str(best_network),
        "matched_side": best_side,
    }


def evaluate(
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
    address_raw: Sequence[str],
) -> list[dict]:
    """Evaluate each address against allow/deny lists by longest-prefix match.

    Inputs are assumed validated already (e.g. by the Pydantic schema); a
    malformed value raises :class:`ValueError`.  Results are returned in the
    same order as ``address_raw``.
    """
    allow_entries: list[tuple[int, Network, str]] = [
        (i, parse_network(item), "allow") for i, item in enumerate(allow_raw)
    ]
    deny_entries: list[tuple[int, Network, str]] = [
        (i, parse_network(item), "deny") for i, item in enumerate(deny_raw)
    ]
    entries = allow_entries + deny_entries

    results: list[dict] = []
    for item in address_raw:
        address = parse_address(item)
        family_entries = [
            (index, network, side)
            for index, network, side in entries
            if network.version == address.version
        ]
        match = _best_match(address, family_entries)
        if match is None:
            results.append(
                {"decision": "unmatched", "matched_cidr": None,
                 "matched_side": None}
            )
        else:
            results.append(match)
    return results


# ---------------------------------------------------------------------------
# compare: decision-constant CIDR partitioning of one scope for two policy
# sets (baseline vs candidate), reusing the evaluate precedence rules.
# ---------------------------------------------------------------------------

#: Possible per-address decisions, including "nothing matches".
DECISIONS: tuple[str, ...] = ("allow", "deny", "unmatched")

#: Every baseline -> candidate transition, in a fixed display order.
TRANSITION_KEYS: tuple[str, ...] = tuple(
    f"{left}->{right}"
    for left in DECISIONS
    for right in DECISIONS
    if left != right
)


def _parse_entries(
    allow_raw: Sequence[str],
    deny_raw: Sequence[str],
    family: type,
) -> list[tuple[int, Network, str]]:
    """Build ``(index, network, side)`` entries for one address family."""
    entries: list[tuple[int, Network, str]] = []
    for index, item in enumerate(allow_raw):
        network = parse_network(item)
        if isinstance(network, family):
            entries.append((index, network, "allow"))
    for index, item in enumerate(deny_raw):
        network = parse_network(item)
        if isinstance(network, family):
            entries.append((index, network, "deny"))
    return entries


def _entry_key(entry: tuple[int, Network, str]) -> tuple[int, int, int]:
    """Match-comparison key shared with :func:`_best_match`."""
    index, network, side = entry
    return network.prefixlen, _SIDE_RANK[side], -index


def _pick_winner(
    entries: Sequence[tuple[int, Network, str]],
) -> tuple[int, Network, str] | None:
    """Best entry by longest-prefix/deny/index priority, or ``None``."""
    return max(entries, key=_entry_key, default=None)


def _winner_side(winner: tuple[int, Network, str] | None) -> str:
    return winner[2] if winner is not None else "unmatched"


def _partition_node(
    network: Network,
    inherited: tuple[int, Network, str] | None,
    entries: Sequence[tuple[int, Network, str]],
    out: list[tuple[Network, str]],
) -> None:
    """Recursively append decision-constant pieces covering ``network``.

    ``inherited`` is the winning entry of a strictly broader prefix (already
    decided at an ancestor); ``entries`` are all entries that are subnets of
    ``network`` (equal or stricter).  A node only needs splitting while it
    contains an entry strictly deeper than itself, mirroring :func:`_diff`:
    untouched halves survive whole, which keeps every piece maximal.
    """
    own = [entry for entry in entries if entry[1] == network]
    strict = [entry for entry in entries if entry[1] != network]
    # An equal-length entry always beats the inherited strictly-broader
    # winner (longest-prefix rule); deny still wins equal-length own ties.
    winner = _pick_winner(own)
    if winner is None:
        winner = inherited

    if not strict or network.prefixlen == _MAX_PREFIXLEN[type(network)]:
        out.append((network, _winner_side(winner)))
        return

    left, right = network.subnets()
    for half in (left, right):
        half_entries = [entry for entry in strict if entry[1].subnet_of(half)]
        _partition_node(half, winner, half_entries, out)


def _decision_partition(
    scope: Network,
    entries: Sequence[tuple[int, Network, str]],
) -> list[tuple[Network, str]]:
    """Partition ``scope`` into maximal CIDRs each having one constant decision.

    Entries equal to or broader than ``scope`` decide the root (longest prefix,
    deny winning equal-length ties); strict subnets force recursive splits.
    The returned pieces are non-overlapping and jointly exhaust ``scope``.
    """
    covering = [
        entry for entry in entries
        if entry[1] == scope or scope.subnet_of(entry[1])
    ]
    root_winner = _pick_winner(covering)
    strict = [
        entry for entry in entries
        if entry[1] != scope and entry[1].subnet_of(scope)
    ]

    pieces: list[tuple[Network, str]] = []
    if not strict:
        pieces.append((scope, _winner_side(root_winner)))
        return pieces

    left, right = scope.subnets()
    for half in (left, right):
        half_entries = [entry for entry in strict if entry[1].subnet_of(half)]
        _partition_node(half, root_winner, half_entries, pieces)
    return pieces


def _overlay_partitions(
    baseline: Sequence[tuple[Network, str]],
    candidate: Sequence[tuple[Network, str]],
) -> list[tuple[Network, str, str]]:
    """Intersect two tilings of the same scope into (cidr, base, candidate).

    Every baseline piece and candidate piece is prefix-aligned, so when two
    pieces overlap one equals or contains the other; the finer network of the
    pair is the intersection.  The result again tiles the whole scope.
    """
    refined: list[tuple[Network, str, str]] = []
    for base_network, base_decision in baseline:
        for cand_network, cand_decision in candidate:
            if not base_network.overlaps(cand_network):
                continue
            if cand_network == base_network or cand_network.subnet_of(base_network):
                refined.append((cand_network, base_decision, cand_decision))
            else:
                # The baseline piece is the finer (strict subnet) one.
                refined.append((base_network, base_decision, cand_decision))
    return refined


def _merge_labelled(
    blocks: Sequence[tuple[Network, str, str]],
) -> list[tuple[Network, str, str]]:
    """Recursively merge complete sibling pairs with identical transition.

    A pair merges only when both halves of one common parent are present and
    both carry the same ``(baseline, candidate)`` label.  The fixpoint loop
    repeats so parents formed by a merge can merge again, just like
    :func:`ipaddress.collapse_addresses` — but adjacent unequal-length
    prefixes, and siblings whose transitions differ, are never joined.
    """
    pieces = list(blocks)
    while True:
        groups: dict[tuple[bytes, int], list[tuple[Network, str, str]]] = {}
        for block in pieces:
            network = block[0]
            if network.prefixlen == 0:
                continue
            parent = network.supernet()
            groups.setdefault(_sort_key(parent), []).append(block)

        merged: list[tuple[Network, str, str]] = []
        consumed: set[int] = set()
        for group in groups.values():
            labels = {block[1:] for block in group}
            if len(group) == 2 and len(labels) == 1:
                parent = group[0][0].supernet()
                merged.append((parent, group[0][1], group[0][2]))
                consumed.update(id(block) for block in group)

        if not merged:
            return pieces
        pieces = merged + [
            block for block in pieces if id(block) not in consumed
        ]


def compare(
    scope_raw: str,
    baseline_allow: Sequence[str],
    baseline_deny: Sequence[str],
    candidate_allow: Sequence[str],
    candidate_deny: Sequence[str],
) -> dict:
    """Compare baseline vs candidate decisions everywhere inside ``scope``.

    Both policy sets are independently partitioned into decision-constant
    CIDRs; the two tilings are overlaid (intersected) and only regions whose
    decision differs survive, after sibling merging by transition type.
    Inputs are assumed validated already (e.g. by the Pydantic schema); a
    malformed value raises :class:`ValueError`.
    """
    scope = parse_network(scope_raw)
    family = type(scope)

    baseline_entries = _parse_entries(baseline_allow, baseline_deny, family)
    candidate_entries = _parse_entries(candidate_allow, candidate_deny, family)

    baseline_parts = _decision_partition(scope, baseline_entries)
    candidate_parts = _decision_partition(scope, candidate_entries)
    refined = _overlay_partitions(baseline_parts, candidate_parts)

    differences = [
        (network, base_decision, cand_decision)
        for network, base_decision, cand_decision in refined
        if base_decision != cand_decision
    ]
    differences = _merge_labelled(differences)
    differences.sort(key=lambda block: _sort_key(block[0]))

    counts = {key: 0 for key in TRANSITION_KEYS}
    for network, base_decision, cand_decision in differences:
        counts[f"{base_decision}->{cand_decision}"] += network.num_addresses

    return {
        "differences": [
            {
                "cidr": str(network),
                "baseline_decision": base_decision,
                "candidate_decision": cand_decision,
            }
            for network, base_decision, cand_decision in differences
        ],
        "transition_counts": {
            key: str(counts[key]) for key in TRANSITION_KEYS
        },
    }
