"""The primary planner is pinned to the authorized model and records billed usage."""
import asyncio
import json

import httpx
import pytest

from worker import intelligence


def test_responses_plan_is_pinned_and_costed(monkeypatch):
    sent=[]
    def handler(request):
        body=json.loads(request.content)
        sent.append(body)
        assert body['model']=='gpt-6-sol'
        assert body['store'] is False
        assert body['max_output_tokens']==3000
        assert body['text']['format']['strict'] is True
        answer={'fault':'minor units multiplied','rollback_risk':'tenant leak and retired field','recommendation':'forward_patch','source':'def handler():\n    pass\n','explanation':'repair the current contract'}
        return httpx.Response(200,json={'id':'resp_test','status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(answer)}]}],'usage':{'input_tokens':2000,'input_tokens_details':{'cached_tokens':500},'output_tokens':300}})
    client=httpx.AsyncClient
    monkeypatch.setattr(intelligence.httpx,'AsyncClient',lambda **kwargs: client(transport=httpx.MockTransport(handler),**kwargs))
    monkeypatch.setattr(intelligence,'key',lambda *args:'test-only-key')
    result=asyncio.run(intelligence.plan('synthetic source',[],[],[]))
    assert len(sent)==1
    assert result['model']=='gpt-6-sol'
    assert result['response_id']=='resp_test'
    assert result['estimated_usd']==0.0061
    assert len(json.dumps(sent[0]['input']))<intelligence.max_input_chars


def test_quota_error_does_not_log_api_body(monkeypatch):
    client=httpx.AsyncClient
    monkeypatch.setattr(intelligence.httpx,'AsyncClient',lambda **kwargs: client(transport=httpx.MockTransport(lambda request:httpx.Response(429,json={'error':{'code':'credit_balance_exhausted','message':'private content'}})),**kwargs))
    monkeypatch.setattr(intelligence,'key',lambda *args:'test-only-key')
    try:
        asyncio.run(intelligence.plan('synthetic source',[],[],[]))
    except intelligence.intelligence_error as exc:
        assert str(exc)=='openai returned http 429 (credit_balance_exhausted)'
    else:
        assert False,'quota error must surface'


def test_large_prompt_stops_before_model_call(monkeypatch):
    monkeypatch.setattr(intelligence,'key',lambda *args:'test-only-key')
    with pytest.raises(intelligence.intelligence_error,match='input budget'):
        asyncio.run(intelligence.plan('x'*intelligence.max_input_chars,[],[],[]))
