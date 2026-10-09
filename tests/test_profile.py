"""Password changes require the current secret and revoke every old credential."""
import asyncio
import uuid

import httpx
from worker import app as webapp, engine


def test_change_password_revokes_sessions_and_api_keys(monkeypatch):
    database_name = 'oopsie_profile_test_' + uuid.uuid4().hex
    database = engine.client[database_name]
    monkeypatch.setattr(webapp.engine, 'db', database)

    async def exercise():
        transport = httpx.ASGITransport(app=webapp.app)
        async with httpx.AsyncClient(transport=transport, base_url='https://app.oopsie.website') as client:
            old = 'owned-demo-password-123'
            new = 'new-owned-demo-password-456'
            assert (await client.post('/api/me/password', json={
                'current_password': old, 'new_password': new})).status_code == 401
            registered = await client.post('/api/auth/register', json={
                'email': 'profile-' + uuid.uuid4().hex + '@oopsie.website', 'password': old})
            assert registered.status_code == 200, registered.text
            user_id = registered.json()['id']
            key = (await client.post('/api/keys')).json()['key']
            assert (await client.post('/api/me/password', json={
                'current_password': 'wrong-password', 'new_password': new})).status_code == 401
            assert (await client.post('/api/me/password', json={
                'current_password': old, 'new_password': old})).status_code == 409
            assert (await client.post('/api/me/password', json={
                'current_password': old, 'new_password': '€' * 30})).status_code == 422
            changed = await client.post('/api/me/password', json={
                'current_password': old, 'new_password': new})
            assert changed.status_code == 200, changed.text
            assert changed.json() == {'ok': True, 'sessions_revoked': True, 'api_keys_revoked': True}
            assert database.sessions.count_documents({'user': user_id}) == 0
            assert database.api_keys.count_documents({'user': user_id}) == 0
            assert (await client.get('/api/me')).status_code == 401
            assert (await client.get('/api/me', headers={'Authorization': 'Bearer ' + key})).status_code == 401
            assert (await client.post('/api/auth/login', json={
                'email': registered.json()['email'], 'password': old})).status_code == 401
            assert (await client.post('/api/auth/login', json={
                'email': registered.json()['email'], 'password': new})).status_code == 200

    try:
        asyncio.run(exercise())
    finally:
        engine.client.drop_database(database_name)
