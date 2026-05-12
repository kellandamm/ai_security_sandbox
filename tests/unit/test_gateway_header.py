import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../app"))

import gateway
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client_with_gateway_secret(monkeypatch):
    monkeypatch.setattr(gateway, "ORCHESTRATOR_GATEWAY_SECRET", "expected-secret")

    app = FastAPI()
    app.add_middleware(gateway.GatewayHeaderMiddleware)

    @app.get("/runs")
    async def runs():
        return {"ok": True}

    @app.post("/runs/test/approve")
    async def approve():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return TestClient(app)


def test_gateway_header_blocks_direct_requests(monkeypatch):
    client = _client_with_gateway_secret(monkeypatch)

    response = client.get("/runs")

    assert response.status_code == 403
    assert response.json()["detail"] == "Requests must enter through API Management."


def test_gateway_header_allows_apim_requests(monkeypatch):
    client = _client_with_gateway_secret(monkeypatch)

    response = client.get(
        "/runs",
        headers={"X-Orchestrator-Gateway-Secret": "expected-secret"},
    )

    assert response.status_code == 200


def test_gateway_header_keeps_health_and_approval_callbacks_available(monkeypatch):
    client = _client_with_gateway_secret(monkeypatch)

    assert client.get("/health").status_code == 200
    assert client.post("/runs/test/approve").status_code == 200