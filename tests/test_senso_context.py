"""the worker must not reason from a stale or edited remote policy body."""
import asyncio
from types import SimpleNamespace

import pytest

from worker import vendors
from worker.config import digest


def test_senso_context_requires_exact_approved_remote_text(monkeypatch):
    monkeypatch.setattr(vendors,'runtime',lambda:{'senso_node':'approved-node','senso_content':'approved-content'})
    monkeypatch.setattr(vendors,'key',lambda *_:'test-key')
    searched=[]
    remote_text='different policy'

    async def fake_request(method,url,**kwargs):
        nonlocal remote_text
        if url.endswith('/approved-node'):
            payload={'content':{'processing_status':'complete'}}
        elif url.endswith('/approved-node/content'):
            payload={'processing_status':'complete','text':remote_text}
        elif url.endswith('/search/context'):
            searched.append(True)
            payload={'results':[{'kb_node_id':'approved-node','version_id':'v2'}]}
        else:
            raise AssertionError(url)
        return SimpleNamespace(json=lambda:payload)

    monkeypatch.setattr(vendors,'request',fake_request)
    with pytest.raises(vendors.vendor_error,match='differs'):
        asyncio.run(vendors.context())
    assert searched==[]

    remote_text=vendors.policy
    result=asyncio.run(vendors.context())
    assert result['policy_hash']==digest(vendors.policy)
    assert result['sources'][0]['version_id']=='v2'
    assert searched==[True]
