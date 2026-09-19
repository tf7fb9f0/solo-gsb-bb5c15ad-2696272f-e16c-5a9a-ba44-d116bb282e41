"""API-level tests for POST /normalize using FastAPI's TestClient."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_normalize_basic():
    response = client.post(
        "/normalize",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
            "deny": ["10.0.0.128/25"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ipv4"] == ["10.0.0.0/25"]
    assert data["ipv6"] == ["2001:db8::/32"]
    assert data["stats"]["allow"] == {
        "input": 3, "unique": 2, "duplicates_removed": 1,
        "ipv4": 1, "ipv6": 1,
    }
    assert data["stats"]["deny"] == {
        "input": 1, "unique": 1, "duplicates_removed": 0,
        "ipv4": 1, "ipv6": 0,
    }
    assert data["stats"]["output"] == {"ipv4": 1, "ipv6": 1, "total": 2}


def test_empty_body_defaults_to_empty_lists():
    response = client.post("/normalize", json={})
    assert response.status_code == 200
    assert response.json() == {
        "ipv4": [],
        "ipv6": [],
        "stats": {
            "allow": {"input": 0, "unique": 0, "duplicates_removed": 0,
                      "ipv4": 0, "ipv6": 0},
            "deny": {"input": 0, "unique": 0, "duplicates_removed": 0,
                     "ipv4": 0, "ipv6": 0},
            "output": {"ipv4": 0, "ipv6": 0, "total": 0},
        },
    }


def test_invalid_cidr_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/24", "bogus"], "deny": []},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)


def test_host_bits_return_422():
    response = client.post(
        "/normalize",
        json={"allow": [], "deny": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_wrong_type_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": [10], "deny": []},
    )
    assert response.status_code == 422


def test_doc_and_openapi_available():
    assert client.get("/docs").status_code == 200
    spec = client.get("/openapi.json").json()
    assert "/normalize" in spec["paths"]
    assert "/evaluate" in spec["paths"]


# --------------------------------------------------------------------------
# POST /evaluate
# --------------------------------------------------------------------------


def test_evaluate_longest_prefix_deny_tie_and_unmatched():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/25", "2001:db8::/32"],
            "deny": ["10.0.0.0/25"],
            "addresses": [
                "10.0.0.1",       # equal-length deny beats allow
                "10.0.0.200",     # only the broader allow covers this
                "192.0.2.1",      # no match at all
                "2001:db8::1",    # IPv6 allow
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == [
        {"decision": "deny", "matched_cidr": "10.0.0.0/25",
         "matched_side": "deny"},
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
        {"decision": "unmatched", "matched_cidr": None, "matched_side": None},
        {"decision": "allow", "matched_cidr": "2001:db8::/32",
         "matched_side": "allow"},
    ]


def test_evaluate_longer_prefix_beats_broader_deny():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24"],
            "deny": ["10.0.0.0/16"],
            "addresses": ["10.0.0.1"],
        },
    )
    assert response.status_code == 200
    assert response.json() == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_preserves_address_order():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24"],
            "deny": ["10.1.0.0/16"],
            "addresses": ["10.1.0.5", "10.0.0.5", "172.16.0.1", "10.0.0.6"],
        },
    )
    assert response.status_code == 200
    assert [item["decision"] for item in response.json()] == [
        "deny", "allow", "unmatched", "allow",
    ]


def test_evaluate_empty_body_defaults_to_empty_lists():
    response = client.post("/evaluate", json={})
    assert response.status_code == 200
    assert response.json() == []


def test_evaluate_invalid_address_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": ["10.0.0.1", "bogus"]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "addresses" for err in detail)


def test_evaluate_address_with_cidr_notation_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "addresses" for err in response.json()["detail"])


def test_evaluate_invalid_cidr_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": ["10.0.0.1/24"], "deny": [], "addresses": ["10.0.0.1"]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)

    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": ["not-a-cidr"], "addresses": []},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_evaluate_wrong_type_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": [10]},
    )
    assert response.status_code == 422


def test_evaluate_openapi_documents_decision_enum():
    spec = client.get("/openapi.json").json()
    operation = spec["paths"]["/evaluate"]["post"]
    # The response model is a bare array of AddressDecision.
    response_schema = spec["components"]["schemas"]["AddressDecision"]
    decision_enum = response_schema["properties"]["decision"]["enum"]
    assert decision_enum == ["allow", "deny", "unmatched"]
    side_variants = response_schema["properties"]["matched_side"]["anyOf"]
    side_enum = next(v["enum"] for v in side_variants if "enum" in v)
    assert side_enum == ["allow", "deny"]
    # Named request/response examples are exposed in the OpenAPI document.
    request_json = operation["requestBody"]["content"]["application/json"]
    assert "longest_prefix_and_deny_tie_break" in request_json["examples"]
    response_json = operation["responses"]["200"]["content"]["application/json"]
    assert "longest_prefix_and_deny_tie_break" in response_json["examples"]


# --------------------------------------------------------------------------
# POST /compare
# --------------------------------------------------------------------------


def test_compare_basic():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"], "deny": []},
            "candidate": {
                "allow": ["10.0.0.0/25"],
                "deny": ["10.0.0.128/26"],
            },
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "differences": [
            {"cidr": "10.0.0.128/26", "baseline_decision": "allow",
             "candidate_decision": "deny"},
            {"cidr": "10.0.0.192/26", "baseline_decision": "allow",
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
    }


def test_compare_sibling_halves_merge():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"]},
            "candidate": {"deny": ["10.0.0.128/26", "10.0.0.192/26"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    # The two equal-transition /26 halves merge into the upper /25.
    assert data["differences"] == [
        {"cidr": "10.0.0.0/25", "baseline_decision": "allow",
         "candidate_decision": "unmatched"},
        {"cidr": "10.0.0.128/25", "baseline_decision": "allow",
         "candidate_decision": "deny"},
    ]
    assert data["transition_counts"]["allow->deny"] == "128"


def test_compare_identical_policies_return_empty():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.0/24"], "deny": ["10.0.0.0/25"]},
            "candidate": {"allow": ["10.0.0.0/24"], "deny": ["10.0.0.0/25"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["differences"] == []
    assert set(data["transition_counts"]) == {
        "allow->deny", "allow->unmatched", "deny->allow",
        "deny->unmatched", "unmatched->allow", "unmatched->deny",
    }
    assert all(value == "0" for value in data["transition_counts"].values())


def test_compare_defaults_missing_policies_to_empty():
    response = client.post("/compare", json={"scope": "10.0.0.0/24"})
    assert response.status_code == 200
    assert response.json()["differences"] == []


def test_compare_ipv6_decimal_string_counts():
    response = client.post(
        "/compare",
        json={
            "scope": "2001:db8::/32",
            "candidate": {"allow": ["2001:db8::/32"]},
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["differences"] == [
        {"cidr": "2001:db8::/32", "baseline_decision": "unmatched",
         "candidate_decision": "allow"},
    ]
    assert data["transition_counts"]["unmatched->allow"] == str(2 ** 96)


def test_compare_invalid_scope_cidr_returns_422():
    response = client.post(
        "/compare",
        json={"scope": "bogus", "baseline": {}, "candidate": {}},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_compare_scope_host_bits_return_422():
    response = client.post(
        "/compare",
        json={"scope": "10.0.0.1/24", "baseline": {}, "candidate": {}},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "scope" for err in response.json()["detail"])


def test_compare_missing_scope_returns_422():
    response = client.post("/compare", json={"baseline": {}, "candidate": {}})
    assert response.status_code == 422
    assert any("scope" in err["loc"] for err in response.json()["detail"])


def test_compare_wrong_scope_type_returns_422():
    response = client.post("/compare", json={"scope": 10})
    assert response.status_code == 422


def test_compare_invalid_nested_cidr_returns_422():
    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "baseline": {"allow": ["10.0.0.1/24"]},
            "candidate": {},
        },
    )
    assert response.status_code == 422
    locs = [tuple(err["loc"]) for err in response.json()["detail"]]
    assert any(loc[-1] == "allow" and "baseline" in loc for loc in locs)

    response = client.post(
        "/compare",
        json={
            "scope": "10.0.0.0/24",
            "candidate": {"deny": ["not-a-cidr"]},
        },
    )
    assert response.status_code == 422
    locs = [tuple(err["loc"]) for err in response.json()["detail"]]
    assert any(loc[-1] == "deny" and "candidate" in loc for loc in locs)


def test_compare_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/compare" in spec["paths"]
    assert spec["components"]["schemas"]["CompareDifference"]["properties"][
        "baseline_decision"
    ]["enum"] == ["allow", "deny", "unmatched"]
    operation = spec["paths"]["/compare"]["post"]
    examples = operation["requestBody"]["content"]["application/json"][
        "examples"
    ]
    assert "deny_supernet_holes" in examples
