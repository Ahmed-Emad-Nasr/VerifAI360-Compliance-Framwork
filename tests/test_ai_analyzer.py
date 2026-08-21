"""Tests for src/ai_analyzer.py's retry/fallback logic — mocked, no real network
calls or API keys required. Covers the improvement where MODEL_FALLBACK_CHAIN is
now actually used (it used to be defined but never consulted)."""

import pytest
from google.genai import errors as genai_errors

from src import ai_analyzer as ai


class _FakeResponse:
    def __init__(self, text):
        self.text = text


class _FakeModels:
    """Stands in for client.models — generate_content() is scripted per test via a
    list of side effects (each either an exception instance or a return value)."""

    def __init__(self, side_effects_by_model):
        self.side_effects_by_model = side_effects_by_model
        self.calls = []

    def generate_content(self, model, contents, config):
        self.calls.append(model)
        queue = self.side_effects_by_model.get(model, [])
        if not queue:
            raise AssertionError(f"No more scripted responses for model {model!r}")
        outcome = queue.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _FakeClient:
    def __init__(self, side_effects_by_model):
        self.models = _FakeModels(side_effects_by_model)


def _api_error(code):
    return genai_errors.APIError(code, {"error": {"message": "boom"}})


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    monkeypatch.setattr(ai.time, "sleep", lambda *_: None)


def _install_fake_client(monkeypatch, side_effects_by_model):
    client = _FakeClient(side_effects_by_model)
    monkeypatch.setattr(ai, "_get_client", lambda api_key: client)
    monkeypatch.setattr(ai, "_get_api_keys", lambda: ["fake-key-1"])
    return client


def test_first_model_succeeds_immediately(monkeypatch):
    ok_response = _FakeResponse('{"evidence_summary": "s", "assessments": []}')
    client = _install_fake_client(monkeypatch, {ai.MODEL_FALLBACK_CHAIN[0]: [ok_response]})
    response, model_used = ai._generate_with_retry(["fake-key-1"], ["prompt"])
    assert model_used == ai.MODEL_FALLBACK_CHAIN[0]
    assert client.models.calls == [ai.MODEL_FALLBACK_CHAIN[0]]


def test_falls_back_to_next_model_after_persistent_503(monkeypatch):
    """A model stuck returning 503 for all its retries should be abandoned in favor
    of the next model in MODEL_FALLBACK_CHAIN, on the SAME api key."""
    first, second = ai.MODEL_FALLBACK_CHAIN[0], ai.MODEL_FALLBACK_CHAIN[1]
    ok_response = _FakeResponse('{"evidence_summary": "s", "assessments": []}')
    client = _install_fake_client(monkeypatch, {
        first: [_api_error(503)] * ai.MAX_RETRIES,
        second: [ok_response],
    })
    response, model_used = ai._generate_with_retry(["fake-key-1"], ["prompt"])
    assert model_used == second
    assert client.models.calls.count(first) == ai.MAX_RETRIES
    assert client.models.calls[-1] == second


def test_quota_exhausted_skips_remaining_models_on_same_key(monkeypatch):
    """A 429 (quota exhausted) means the WHOLE key/account is out of quota — no other
    model on that same key will help, so it should move straight to the next key
    rather than wasting calls trying sibling models on the exhausted key."""
    first = ai.MODEL_FALLBACK_CHAIN[0]
    ok_response = _FakeResponse('{"evidence_summary": "s", "assessments": []}')

    key_to_client = {
        "key-1": _FakeClient({first: [_api_error(429)]}),
        "key-2": _FakeClient({first: [ok_response]}),
    }
    monkeypatch.setattr(ai, "_get_client", lambda api_key: key_to_client[api_key])

    response, model_used = ai._generate_with_retry(["key-1", "key-2"], ["prompt"])
    assert model_used == first
    # Only ONE call was made on key-1 (the 429), not one per model in the chain.
    assert key_to_client["key-1"].models.calls == [first]
    assert key_to_client["key-2"].models.calls == [first]


def test_non_retryable_error_falls_through_to_next_model(monkeypatch):
    """A non-retryable error (e.g. 400 malformed request) shouldn't loop retrying
    the same model, but should still let the fallback chain try the next model."""
    first, second = ai.MODEL_FALLBACK_CHAIN[0], ai.MODEL_FALLBACK_CHAIN[1]
    ok_response = _FakeResponse('{"evidence_summary": "s", "assessments": []}')
    client = _install_fake_client(monkeypatch, {
        first: [_api_error(400)],
        second: [ok_response],
    })
    response, model_used = ai._generate_with_retry(["fake-key-1"], ["prompt"])
    assert model_used == second
    assert client.models.calls.count(first) == 1  # no retries wasted on a non-retryable error


def test_all_keys_and_models_exhausted_raises(monkeypatch):
    all_fail = {m: [_api_error(503)] * ai.MAX_RETRIES for m in ai.MODEL_FALLBACK_CHAIN}
    _install_fake_client(monkeypatch, all_fail)
    with pytest.raises(ai.AIAnalyzerError):
        ai._generate_with_retry(["fake-key-1"], ["prompt"])


def test_analyze_evidence_reports_model_used(monkeypatch):
    ok_response = _FakeResponse(
        '{"evidence_summary": "looks fine", "assessments": ['
        '{"sub_requirement_id": "1.1", "sufficiency_score": 80, "maturity_level": "Managed", '
        '"rationale": "r", "gaps": [], "recommendations": []}]}'
    )
    _install_fake_client(monkeypatch, {ai.MODEL_FALLBACK_CHAIN[0]: [ok_response]})
    result = ai.analyze_evidence("some evidence text", {"requirements": []})
    assert result["_model_used"] == ai.MODEL_FALLBACK_CHAIN[0]
