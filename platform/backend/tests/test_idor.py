<<<<<<< HEAD
# Author: Avinash Krishna — Team AVV Elites (SIH26153)
=======
>>>>>>> 77949f2bb89fea05df3ee4faf24abd4771ef1671
"""
platform/backend/tests/test_idor.py
SECURITY.md ref: §2 in full. This is THE test file for the IDOR requirement
— every resource type gets a same-shape test: create it as org A, attempt
to read/list/delete it as org B, assert org B is treated exactly as if the
resource doesn't exist (404, never 403 — see deps.py::owned_or_404 for why).
"""
from __future__ import annotations

from tests.conftest import login, register_and_verify


def _bearer(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _setup_two_orgs(client, email_backend):
    register_and_verify(client, email_backend, email="alice@org-a.io", full_name="Alice", org="Org A")
    tokens_a = login(client, email="alice@org-a.io")

    register_and_verify(client, email_backend, email="bob@org-b.io", full_name="Bob", org="Org B")
    tokens_b = login(client, email="bob@org-b.io")

    return tokens_a, tokens_b


def test_user_cannot_list_another_orgs_segments(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)

    client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))

    res_b = client.get("/api/segments", headers=_bearer(tokens_b))
    assert res_b.status_code == 200
    assert res_b.json() == [], "org B must not see org A's segments in its own list endpoint"


def test_user_cannot_read_another_orgs_segment_by_id(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)

    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    # org A can read its own segment
    own_res = client.get(f"/api/segments/{segment_id}", headers=_bearer(tokens_a))
    assert own_res.status_code == 200

    # org B must be denied — and specifically with 404, not 403, so the
    # response gives no signal that the ID even exists (SECURITY.md §2)
    cross_res = client.get(f"/api/segments/{segment_id}", headers=_bearer(tokens_b))
    assert cross_res.status_code == 404


def test_user_cannot_delete_another_orgs_segment(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)
    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    delete_res = client.delete(f"/api/segments/{segment_id}", headers=_bearer(tokens_b))
    assert delete_res.status_code == 404

    # confirm it's genuinely still there for org A (the delete attempt did not silently succeed)
    still_there = client.get(f"/api/segments/{segment_id}", headers=_bearer(tokens_a))
    assert still_there.status_code == 200


def test_user_cannot_create_forecast_under_another_orgs_segment(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)
    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    # org B tries to run/attach a forecast to org A's segment id directly
    res = client.post(
        f"/api/segments/{segment_id}/forecasts/demo-sample",
        headers=_bearer(tokens_b),
    )
    assert res.status_code == 404, "org B must not be able to attach a forecast to org A's segment"


def test_user_cannot_list_forecasts_by_guessing_another_orgs_segment_id(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)
    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    # even filtering the (org-scoped) /forecasts list by another org's
    # segment_id query param must not leak anything
    res = client.get(f"/api/forecasts?segment_id={segment_id}", headers=_bearer(tokens_b))
    assert res.status_code == 404


def test_user_cannot_read_or_delete_another_orgs_forecast_by_id(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)
    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    forecast_res = client.post(f"/api/segments/{segment_id}/forecasts/demo-sample", headers=_bearer(tokens_a))
    if forecast_res.status_code == 503:
        import pytest
        pytest.skip("ML checkpoints not trained in this environment — run `python -m src.train` first.")
    assert forecast_res.status_code == 201
    forecast_id = forecast_res.json()["id"]

    read_cross = client.get(f"/api/forecasts/{forecast_id}", headers=_bearer(tokens_b))
    assert read_cross.status_code == 404

    delete_cross = client.delete(f"/api/forecasts/{forecast_id}", headers=_bearer(tokens_b))
    assert delete_cross.status_code == 404

    still_there = client.get(f"/api/forecasts/{forecast_id}", headers=_bearer(tokens_a))
    assert still_there.status_code == 200


def test_copilot_explain_is_idor_scoped_to_forecast_owner(client, email_backend):
    tokens_a, tokens_b = _setup_two_orgs(client, email_backend)
    create_res = client.post("/api/segments", json={"name": "org-a-corp-lan"}, headers=_bearer(tokens_a))
    segment_id = create_res.json()["id"]

    forecast_res = client.post(f"/api/segments/{segment_id}/forecasts/demo-sample", headers=_bearer(tokens_a))
    if forecast_res.status_code == 503:
        import pytest
        pytest.skip("ML checkpoints not trained in this environment — run `python -m src.train` first.")
    forecast_id = forecast_res.json()["id"]

    cross_res = client.post("/api/copilot/explain", json={"forecast_id": forecast_id}, headers=_bearer(tokens_b))
    assert cross_res.status_code == 404


def test_unauthenticated_requests_to_resource_routes_are_rejected(client):
    """Sanity check that ownership scoping isn't the ONLY thing standing
    between an anonymous caller and these routes — auth is required first."""
    assert client.get("/api/segments").status_code == 401
    assert client.get("/api/forecasts").status_code == 401
    assert client.post("/api/segments", json={"name": "x"}).status_code == 401
