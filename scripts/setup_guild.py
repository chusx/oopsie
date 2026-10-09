"""provision hosted investigator and coordinator using guild's public account-key api."""
import asyncio
import json
from worker.config import root, runtime, save_runtime
from worker.vendors import guild

owner='01a121e0-d416-0175-0000-8b4fdc2e0d36'

roles={
 'investigator': '''you are the oopsie investigator for a synthetic owner-approved billing sandbox. read the structured counterexamples and approved recovery floor in the prompt. return a single compact json object: {"fault":"...", "rollback_risk":"...", "recommendation":"forward_patch" or "needs_attention", "confidence":"high" or "low"}. mention only things supported by the prompt. the service may return 200 while wrong. tenant boundary and current schema must survive. answer in lowercase.''',
 'coordinator': '''you are the oopsie recovery coordinator for an owner-approved synthetic billing sandbox. read the investigator's finding, current recovery policy, and clickhouse observation receipt. output a single compact json object: {"action":"recover" or "needs_attention", "reason":"..."}. choose recover only for an evidenced current-release contract violation and auto mode. the worker will independently reject unsafe code and verify public traffic. never claim a recovery already happened. answer in lowercase.'''
}
async def main():
    cfg=runtime()
    if not cfg.get('guild_workspace'):
        ws=await guild('POST','/workspaces',{'name':'oopsie-ops','owner_id':owner})
        cfg=save_runtime({'guild_workspace':ws['id']})
        print('workspace created',ws['id'])
    for role,prompt in roles.items():
        field='guild_'+role
        if not cfg.get(field):
            agent=await guild('POST','/agents',{'name':'oopsie-'+role,'description':'oopsie '+role+' for evidenced synthetic api recovery','owner_id':owner,'is_public':False,'template':'LLM'})
            cfg=save_runtime({field:agent['id']})
            print(role,'created',agent['id'])
        if not cfg.get(field+'_configured'):
            for attempt in range(60):
                listing=await guild('GET',f"/agents/{cfg[field]}/versions")
                if listing['items'] and listing['items'][0]['validation_status']=='PASSED': break
                await asyncio.sleep(3)
            version=await guild('POST',f"/agents/{cfg[field]}/configure-llm",{'system_prompt':prompt,'description':'bounded oopsie '+role,'tools':[],'guild_tools':['guild_search_agent'],'mode':'one-shot','version_number':'1.0.1'})
            cfg=save_runtime({field+'_configured':True,field+'_version':version['id']})
            print(role,'configured',version['id'])
        if not cfg.get(field+'_published'):
            for attempt in range(60):
                listing=await guild('GET',f"/agents/{cfg[field]}/versions")
                version=next((x for x in listing['items'] if x['id']==cfg[field+'_version']),None)
                if version and version['status']=='PUBLISHED': break
                if version and version['validation_status']=='PASSED':
                    try: await guild('POST',f"/versions/{cfg[field+'_version']}/publish",{})
                    except Exception: pass
                elif version and version['validation_status']=='FAILED': raise RuntimeError(role+' validation failed')
                await asyncio.sleep(3)
            else: raise RuntimeError(role+' validation timed out')
            cfg=save_runtime({field+'_published':True})
            print(role,'published')
    for role in roles:
        field='guild_'+role
        if not cfg.get(field+'_installation'):
            installed=await guild('POST',f"/workspaces/{cfg['guild_workspace']}/workspace_agents",{'agent_id':cfg[field],'should_autoupdate':True})
            cfg=save_runtime({field+'_installation':installed['id']})
            print(role,'installed',installed['id'])
    save_runtime({'guild_agent':cfg['guild_coordinator']})
    print('guild hosted team ready')
if __name__=='__main__': asyncio.run(main())
