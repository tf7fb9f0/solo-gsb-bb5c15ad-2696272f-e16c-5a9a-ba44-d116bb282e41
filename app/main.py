"""FastAPI application exposing POST /normalize, /evaluate and /compare."""

from __future__ import annotations

from fastapi import FastAPI

from app.policy import compare, evaluate, normalize
from app.schemas import (
    AddressDecision,
    CompareRequest,
    CompareResponse,
    EvaluateRequest,
    NormalizeResponse,
    PolicyRequest,
)

app = FastAPI(
    title="CIDR Policy Normalizer",
    description=(
        "Compute allow-minus-deny for IPv4/IPv6 CIDR lists, returning the "
        "equivalent, non-overlapping, minimum-count CIDR set; evaluate "
        "individual addresses against the same lists via longest-prefix "
        "match; and diff two policy sets (baseline vs candidate) over a "
        "scope CIDR."
    ),
    version="1.2.0",
)


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/normalize",
    response_model=NormalizeResponse,
    tags=["policy"],
    summary="Normalize allow/deny CIDR lists into allow minus deny",
)
def normalize_policy(request: PolicyRequest) -> dict:
    return normalize(request.allow, request.deny)


@app.post(
    "/evaluate",
    response_model=list[AddressDecision],
    tags=["policy"],
    summary="Evaluate addresses by longest-prefix match against allow/deny",
    openapi_extra={
        # FastAPI drops Body(examples=...) for model-typed parameters, so the
        # named request examples are attached via openapi_extra; FastAPI merges
        # them into the generated requestBody alongside the schema $ref.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins equal-length ties",
                            "value": {
                                "allow": [
                                    "10.0.0.0/24", "10.0.0.0/25",
                                    "2001:db8::/32",
                                ],
                                "deny": ["10.0.0.0/25"],
                                "addresses": [
                                    "10.0.0.1", "10.0.0.200",
                                    "192.0.2.1", "2001:db8::1",
                                ],
                            },
                        },
                        "invalid_address": {
                            "summary": "CIDR notation in addresses -> HTTP 422",
                            "value": {
                                "allow": ["10.0.0.0/8"],
                                "deny": [],
                                "addresses": ["10.0.0.1/24"],
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": "One decision per input address, in input order.",
            "content": {
                "application/json": {
                    "examples": {
                        "longest_prefix_and_deny_tie_break": {
                            "summary": "Longest prefix wins; deny wins ties",
                            "value": [
                                {"decision": "deny",
                                 "matched_cidr": "10.0.0.0/25",
                                 "matched_side": "deny"},
                                {"decision": "allow",
                                 "matched_cidr": "10.0.0.0/24",
                                 "matched_side": "allow"},
                                {"decision": "unmatched",
                                 "matched_cidr": None,
                                 "matched_side": None},
                                {"decision": "allow",
                                 "matched_cidr": "2001:db8::/32",
                                 "matched_side": "allow"},
                            ],
                        },
                    },
                },
            },
        },
        422: {"description": "An address or CIDR in the request is invalid."},
    },
)
def evaluate_policy(request: EvaluateRequest) -> list[dict]:
    return evaluate(request.allow, request.deny, request.addresses)


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["policy"],
    summary="Diff baseline vs candidate decisions within a scope CIDR",
    openapi_extra={
        # See /evaluate: named body examples survive only via openapi_extra
        # for model-typed parameters.
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": (
                                "Candidate denies a /26 inside the baseline "
                                "allow; deny wins the equal-length tie below"
                            ),
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {
                                    "allow": ["10.0.0.0/24"],
                                    "deny": [],
                                },
                                "candidate": {
                                    "allow": ["10.0.0.0/25"],
                                    "deny": ["10.0.0.128/26"],
                                },
                            },
                        },
                        "identical_policies": {
                            "summary": "Identical sets -> no differences",
                            "value": {
                                "scope": "10.0.0.0/24",
                                "baseline": {"allow": ["10.0.0.0/24"]},
                                "candidate": {"allow": ["10.0.0.0/24"]},
                            },
                        },
                    },
                },
            },
        },
    },
    responses={
        200: {
            "description": (
                "Differing regions within scope, sibling-merged per "
                "transition type, plus per-transition address totals."
            ),
            "content": {
                "application/json": {
                    "examples": {
                        "deny_supernet_holes": {
                            "summary": "Two allow->deny regions",
                            "value": {
                                "differences": [
                                    {"cidr": "10.0.0.128/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "deny"},
                                    {"cidr": "10.0.0.192/26",
                                     "baseline_decision": "allow",
                                     "candidate_decision": "unmatched"},
                                ],
                                "transition_counts": {
                                    "allow->deny": "64",
                                    "allow->unmatched": "64",
                                    "deny->allow": "0",
                                    "deny->unmatched": "0",
                                    "unmatched->allow": "0",
                                    "unmatched->deny": "0",
                                },
                            },
                        },
                    },
                },
            },
        },
        422: {"description": "The scope or a CIDR entry is invalid."},
    },
)
def compare_policies(request: CompareRequest) -> dict:
    return compare(
        request.scope,
        request.baseline.allow,
        request.baseline.deny,
        request.candidate.allow,
        request.candidate.deny,
    )
