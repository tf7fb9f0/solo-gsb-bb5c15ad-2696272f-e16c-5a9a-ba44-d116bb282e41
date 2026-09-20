"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.policy import _MAX_PREFIXLEN, parse_address, parse_network


class PolicyRequest(BaseModel):
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list (IPv4/IPv6 may be mixed).",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list (IPv4/IPv6 may be mixed).",
    )

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        for value in values:
            parse_network(value)
        return values


class EvaluateRequest(PolicyRequest):
    addresses: list[str] = Field(
        default_factory=list,
        description="Bare IPv4/IPv6 addresses to evaluate, in response order.",
    )

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_address(value)
        return values


class ListStats(BaseModel):
    input: int = Field(description="Raw number of entries in the request list.")
    unique: int = Field(description="Distinct networks after de-duplication.")
    duplicates_removed: int = Field(description="input - unique.")
    ipv4: int = Field(description="Distinct IPv4 networks after de-duplication.")
    ipv6: int = Field(description="Distinct IPv6 networks after de-duplication.")


class OutputStats(BaseModel):
    ipv4: int
    ipv6: int
    total: int


class Stats(BaseModel):
    allow: ListStats
    deny: ListStats
    output: OutputStats


class NormalizeResponse(BaseModel):
    ipv4: list[str] = Field(
        description="allow - deny for IPv4, minimal, non-overlapping, sorted.",
    )
    ipv6: list[str] = Field(
        description="allow - deny for IPv6, minimal, non-overlapping, sorted.",
    )
    stats: Stats


class AddressDecision(BaseModel):
    decision: Literal["allow", "deny", "unmatched"] = Field(
        description=(
            "Winner side after longest-prefix matching; 'unmatched' when no "
            "list entry contains the address."
        ),
    )
    matched_cidr: str | None = Field(
        description="Canonical CIDR of the winning entry; null when unmatched.",
    )
    matched_side: Literal["allow", "deny"] | None = Field(
        description="List the winning entry came from; null when unmatched.",
    )


class CompareRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) limiting the comparison region. "
            "Strict: host bits must be zero."
        ),
    )
    baseline: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Baseline allow/deny policy set.",
    )
    candidate: PolicyRequest = Field(
        default_factory=PolicyRequest,
        description="Candidate allow/deny policy set to compare against.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        # A missing/blank scope is invalid; a bare address (host prefix) is
        # accepted, just like allow/deny entries.
        parse_network(value)
        return value


class CompareDifference(BaseModel):
    cidr: str = Field(
        description="Non-overlapping region inside scope where decisions differ.",
    )
    baseline_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Baseline decision throughout cidr.",
    )
    candidate_decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Candidate decision throughout cidr.",
    )


class CompareResponse(BaseModel):
    differences: list[CompareDifference] = Field(
        description=(
            "Regions whose decision changes, sorted IPv4 then IPv6, by "
            "network address then prefix length."
        ),
    )
    transition_counts: dict[str, str] = Field(
        description=(
            "Addresses covered per 'baseline->candidate' transition type, "
            "as decimal strings; all six transitions are present (0 when "
            "unused)."
        ),
    )


class AllocationRequest(BaseModel):
    id: str = Field(
        min_length=1,
        description="Caller-chosen request identifier; must be unique.",
    )
    prefix_length: int = Field(
        ge=0,
        description=(
            "Requested subnet prefix length; must fit the scope address "
            "family (0-32 for IPv4, 0-128 for IPv6)."
        ),
    )


class AllocateRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) the allocations are carved from. "
            "Strict: host bits must be zero."
        ),
    )
    occupied: list[str] = Field(
        default_factory=list,
        description=(
            "Already-allocated CIDRs. Each must share the scope address "
            "family, lie inside the scope, and not overlap any other entry."
        ),
    )
    requests: list[AllocationRequest] = Field(
        default_factory=list,
        description="Subnet requests, allocated in this order.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("occupied")
    @classmethod
    def _validate_occupied_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_against_scope(self) -> "AllocateRequest":
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response, exactly like the per-field validators above.
        scope = parse_network(self.scope)
        max_prefixlen = _MAX_PREFIXLEN[type(scope)]

        networks = [parse_network(value) for value in self.occupied]
        for network in networks:
            if not isinstance(network, type(scope)):
                raise ValueError(
                    f"occupied CIDR {network} does not match the scope "
                    f"address family ({scope})"
                )
            if not network.subnet_of(scope):
                raise ValueError(
                    f"occupied CIDR {network} is not contained in scope "
                    f"{scope}"
                )
        ordered = sorted(
            networks, key=lambda n: (int(n.network_address), n.prefixlen)
        )
        # For intervals sorted by start, any overlap implies an overlap of
        # some consecutive pair.
        for left, right in zip(ordered, ordered[1:]):
            if left.overlaps(right):
                raise ValueError(
                    f"occupied CIDRs {left} and {right} overlap"
                )

        seen: set[str] = set()
        for item in self.requests:
            if item.id in seen:
                raise ValueError(f"duplicate request id {item.id!r}")
            seen.add(item.id)
            if item.prefix_length > max_prefixlen:
                raise ValueError(
                    f"prefix_length {item.prefix_length} exceeds "
                    f"/{max_prefixlen} for the scope address family"
                )
        return self


class Allocation(BaseModel):
    id: str = Field(description="Identifier of the fulfilled request.")
    cidr: str = Field(
        description="Allocated subnet, canonical CIDR, inside the scope.",
    )


class AllocateResponse(BaseModel):
    allocations: list[Allocation] = Field(
        description=(
            "One entry per request, in request order; the sequence of "
            "network addresses is the lexicographically smallest complete "
            "feasible assignment."
        ),
    )
    remaining: list[str] = Field(
        description=(
            "Free space left in the scope after allocation: minimal, "
            "non-overlapping CIDR set, sorted by network address."
        ),
    )
    remaining_addresses: str = Field(
        description=(
            "Total free addresses left in the scope, as a decimal string "
            "(IPv6 remainders exceed JSON's safe integer range)."
        ),
    )
