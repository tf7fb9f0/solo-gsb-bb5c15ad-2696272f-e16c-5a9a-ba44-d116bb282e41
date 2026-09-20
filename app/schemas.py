"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.policy import parse_address, parse_network


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


# ---------------------------------------------------------------------------
# /allocate
# ---------------------------------------------------------------------------


class AllocationRequestItem(BaseModel):
    id: str = Field(
        description="Client-chosen identifier echoed back; must be unique.",
    )
    prefix_length: int = Field(
        ge=0,
        description=(
            "Requested subnet prefix length within the scope family "
            "(0-32 for IPv4, 0-128 for IPv6)."
        ),
    )


class AllocateRequest(BaseModel):
    scope: str = Field(
        description=(
            "Single CIDR (IPv4 or IPv6) that every occupied network and "
            "allocation must lie inside. Strict: host bits must be zero."
        ),
    )
    occupied: list[str] = Field(
        default_factory=list,
        description=(
            "Already-used CIDRs: same family as scope, contained in scope, "
            "pairwise non-overlapping; duplicates are rejected."
        ),
    )
    requests: list[AllocationRequestItem] = Field(
        default_factory=list,
        description="Subnet requests in the order the response must follow.",
    )

    @field_validator("scope")
    @classmethod
    def _validate_scope(cls, value: str) -> str:
        parse_network(value)
        return value

    @field_validator("occupied")
    @classmethod
    def _validate_occupied_strings(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_network(value)
        return values

    @model_validator(mode="after")
    def _validate_allocation_inputs(self) -> AllocateRequest:
        # Scope alone being malformed aborts the cross-field checks; the
        # scope field validator already produced the 422 error for it.
        scope = parse_network(self.scope)

        occupied_nets = [parse_network(value) for value in self.occupied]
        for network in occupied_nets:
            if network.version != scope.version:
                raise ValueError(
                    f"occupied {network} is not the same address family as "
                    f"scope {scope}"
                )
            if not network.subnet_of(scope):
                raise ValueError(
                    f"occupied {network} is not contained in scope {scope}"
                )
        for i, left in enumerate(occupied_nets):
            for right in occupied_nets[i + 1:]:
                if left.overlaps(right):
                    raise ValueError(
                        f"occupied networks overlap: {left} and {right}"
                    )

        seen_ids: set[str] = set()
        max_prefixlen = scope.max_prefixlen
        for item in self.requests:
            if item.prefix_length > max_prefixlen:
                raise ValueError(
                    f"prefix_length {item.prefix_length} exceeds the "
                    f"{scope.version} family maximum of {max_prefixlen}"
                )
            if item.id in seen_ids:
                raise ValueError(f"duplicate request id: {item.id!r}")
            seen_ids.add(item.id)
        return self


class AllocationItem(BaseModel):
    id: str = Field(description="Echoed request identifier.")
    cidr: str = Field(
        description="Allocated aligned subnet, canonical strict CIDR.",
    )


class AllocateResponse(BaseModel):
    allocations: list[AllocationItem] = Field(
        description="One allocation per request, in request order.",
    )
    remaining: list[str] = Field(
        description=(
            "Minimum, non-overlapping CIDR set left in scope after subtracting "
            "occupied and allocated networks; sorted by network address."
        ),
    )
    remaining_addresses: str = Field(
        description="Total addresses covered by remaining, as a decimal string.",
    )
