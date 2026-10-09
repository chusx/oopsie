"""Workspace-scoped, read-only watches for outside signals."""
import asyncio
import secrets
import time
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from . import engine, realworld_sources, realworld_urls

db = engine.db


class watch_error(Exception):
    pass


def public_watch(item):
    if item is None:
        return None
    return {key: value for key, value in item.items() if key not in {'_id', 'verification_token', 'lease_until'}}


def normalize(kind, value, expected_status=200, marker=''):
    try:
        if kind == 'github':
            return realworld_sources.normalize_github(value), {}
        if kind == 'cve':
            return realworld_sources.normalize_cve(value), {}
        if kind == 'url':
            url = realworld_urls.normalize_url(value)
            realworld_urls.validate_contract(expected_status, marker)
            return url, {'expected_status': expected_status, 'marker': marker}
    except (realworld_sources.source_error, realworld_urls.url_watch_error) as exc:
        raise watch_error(str(exc))
    raise watch_error('choose github, cve, or url')


def source_change(kind, previous, current):
    """Describe a bounded, observed change without inferring exploitability."""
    if not previous or previous.get('error'):
        return 'baseline established'
    if kind == 'github':
        before, after = int(previous.get('total_matches', 0)), int(current.get('total_matches', 0))
        if after != before:
            return f'advisory matches changed: {before} → {after}'
        if current.get('commit') != previous.get('commit'):
            return 'repository commit changed; advisory count unchanged'
        if current.get('findings') != previous.get('findings'):
            return 'advisory list changed; count unchanged'
        return 'no change in the checked commit or advisory matches'
    if kind == 'cve':
        if current.get('state') != previous.get('state'):
            return f'record state changed: {previous.get("state", "unknown")} → {current.get("state", "unknown")}'
        if current.get('updated') != previous.get('updated'):
            return 'official record update timestamp changed'
        return 'no change in the official record state or update timestamp'
    changed = [field for field in ('status', 'marker_matched', 'body_sha256')
               if current.get(field) != previous.get(field)]
    return ('response changed: ' + ', '.join(changed)) if changed else 'no change in status, marker, or response hash'


async def create_watch(workspace, kind, value, expected_status=200, marker=''):
    value, extra = normalize(kind, value, expected_status, marker)
    existing = db.watch_targets.find_one({'workspace': workspace, 'kind': kind, 'value': value})
    if existing:
        if kind == 'url' and any(existing.get(key) != extra[key] for key in ('expected_status', 'marker')):
            raise watch_error('remove the existing url watch before changing its expected response')
        return public_watch(existing)
    if db.watch_targets.count_documents({'workspace': workspace}) >= 9:
        raise watch_error('this workspace already has nine watches')
    if db.watch_targets.count_documents({}) >= 300:
        raise watch_error('watch capacity reached')
    now = time.time()
    item = {'id': engine.uid(), 'workspace': workspace, 'kind': kind, 'value': value,
        'state': 'pending', 'created_at': now, 'checked_at': None, 'next_check_at': now,
        'result': {}, 'history': [], **extra}
    if kind == 'url':
        token = secrets.token_urlsafe(18)
        item['verification_token'] = token
        item['state'] = 'awaiting verification'
        item['next_check_at'] = None
        item['result'] = {'verification': {'record': realworld_urls.verification_record(value),
            'value': 'oopsie=' + token}}
    try:
        db.watch_targets.insert_one(item)
    except DuplicateKeyError:
        existing = db.watch_targets.find_one({'workspace': workspace, 'kind': kind, 'value': value})
        if existing:
            return public_watch(existing)
        raise watch_error('watch is already being created')
    if kind == 'url':
        return public_watch(item)
    return await refresh_watch(workspace, item['id'])


async def verify_url_watch(workspace, watch_id):
    item = db.watch_targets.find_one({'id': watch_id, 'workspace': workspace})
    if not item:
        raise watch_error('watch not found in this workspace')
    if item['kind'] != 'url':
        raise watch_error('only custom urls require ownership verification')
    if item.get('verified_at'):
        return public_watch(item)
    try:
        matched = await realworld_urls.verify_dns(item['value'], item['verification_token'])
    except realworld_urls.url_watch_error as exc:
        raise watch_error(str(exc))
    if not matched:
        raise watch_error('dns txt record not found yet; add the exact challenge and retry')
    now = time.time()
    db.watch_targets.update_one({'id': watch_id, 'workspace': workspace},
        {'$set': {'verified_at': now, 'state': 'pending', 'next_check_at': now}})
    return await refresh_watch(workspace, watch_id)


async def refresh_watch(workspace, watch_id, manual=False):
    now = time.time()
    item = db.watch_targets.find_one({'id': watch_id, 'workspace': workspace})
    if not item:
        raise watch_error('watch not found in this workspace')
    if item['kind'] == 'url' and not item.get('verified_at'):
        raise watch_error('verify dns ownership before checking this url')
    if manual and item.get('checked_at') and item['checked_at'] > now - 60:
        raise watch_error('wait one minute before refreshing this watch')
    claimed = db.watch_targets.find_one_and_update(
        {'id': watch_id, 'workspace': workspace,
            '$or': [{'lease_until': {'$lt': now}}, {'lease_until': {'$exists': False}}]},
        {'$set': {'lease_until': now + 120}}, return_document=ReturnDocument.AFTER)
    if not claimed:
        raise watch_error('watch check already running')
    try:
        if claimed['kind'] == 'github':
            result = await realworld_sources.scan_github(claimed['value'])
            matches = int(result.get('total_matches', 0))
            scanned = int(result.get('dependencies_scanned', 0))
            state = ('unsupported' if result.get('status') == 'unsupported' or not scanned else
                'matches' if matches else 'partial' if result.get('partial') else 'no matches')
            summary = (f'{matches} advisory matches in {scanned} pinned versions' if scanned else
                'no supported pinned manifest found')
            interval = 6 * 3600
        elif claimed['kind'] == 'cve':
            result = await realworld_sources.scan_cve(claimed['value'])
            state = 'published' if str(result.get('state', '')).upper() == 'PUBLISHED' else 'reserved'
            summary = 'official cve record ' + state
            interval = 6 * 3600
        else:
            result = await realworld_urls.scan_url(claimed['value'], claimed['expected_status'], claimed.get('marker', ''))
            state = 'passing' if result['passed'] else 'failing'
            summary = f'http {result["status"]}; expected contract {state}'
            interval = 15 * 60
    except (realworld_sources.source_error, realworld_urls.url_watch_error) as exc:
        result = {'error': str(exc)}
        state, summary, interval = 'needs attention', 'source check unavailable', 15 * 60
    except Exception:
        result = {'error': 'source temporarily unavailable'}
        state, summary, interval = 'needs attention', 'source check unavailable', 15 * 60
    if state != 'needs attention':
        result['change'] = source_change(claimed['kind'], claimed.get('result') if claimed.get('checked_at') else None, result)
        if result['change'] != 'baseline established':
            summary += '; ' + result['change']
    checked = time.time()
    db.watch_targets.update_one({'id': watch_id, 'workspace': workspace},
        {'$set': {'state': state, 'result': result, 'checked_at': checked, 'next_check_at': checked + interval},
            '$unset': {'lease_until': ''},
            '$push': {'history': {'$each': [{'at': checked, 'state': state, 'summary': summary}], '$slice': -12}}})
    return public_watch(db.watch_targets.find_one({'id': watch_id, 'workspace': workspace}))


async def monitor_watches():
    """Refresh a bounded number of due targets each minute; no external deployment."""
    while True:
        await asyncio.sleep(60)
        due = list(db.watch_targets.find({'next_check_at': {'$lte': time.time()},
            'state': {'$ne': 'awaiting verification'}}).sort('next_check_at', 1).limit(4))
        for item in due:
            try:
                await refresh_watch(item['workspace'], item['id'])
            except watch_error:
                pass
