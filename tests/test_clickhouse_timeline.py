"""the release trace must stay workspace-scoped and read actual aggregate rows."""
import asyncio
import pytest
from worker import vendors


def test_release_timeline_scopes_query_and_orders_rows(monkeypatch):
    queries=[]
    async def query(sql):
        queries.append(sql)
        return {'rows':[
            {'minute':'2026-10-09 20:40:00','release':'new','probes':10,'failures':0},
            {'minute':'2026-10-09 20:39:00','release':'old','probes':10,'failures':2},
        ],'statistics':{'elapsed_ms':6.5,'rows_read':100,'bytes_read':2000},'query_id':'query-test'}
    monkeypatch.setattr(vendors,'ch_query',query)
    result=asyncio.run(vendors.release_timeline('workspace123','service456'))
    assert result['rows'][0]['release']=='old'
    assert result['rows'][1]['failures']==0
    assert result['query_id']=='query-test'
    assert "workspace='workspace123' AND service='service456'" in queries[0]
    assert 'GROUP BY minute, release' in queries[0]
    with pytest.raises(ValueError,match='invalid query identity'):
        asyncio.run(vendors.release_timeline("workspace' OR 1=1",'service456'))
    assert len(queries)==1
