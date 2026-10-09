"""bounded, read-only public source lookups; never authorizes a recovery action."""

import base64
import binascii
from datetime import datetime, timezone
import json
import re
from urllib.parse import quote, urlsplit

import httpx


class source_error(Exception):
    """a public source is invalid, unavailable, or incomplete."""


_GITHUB_BASE = 'https://api.github.com'
_OSV_BATCH = 'https://api.osv.dev/v1/querybatch'
_CVE_BASE = 'https://cveawg.mitre.org/api/cve'
_ALLOWED_HOSTS = frozenset({'api.github.com', 'api.osv.dev', 'cveawg.mitre.org'})
_SLUG_PART = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
_CVE_ID = re.compile(r'CVE-(\d{4})-(\d{4,10})\Z', re.I)
_NPM_VERSION = re.compile(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z')
_NPM_NAME = re.compile(r'(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+\Z')
_PYPI_PIN = re.compile(r'([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._-]+\])?==([A-Za-z0-9][A-Za-z0-9._+!-]*)\Z')
_PACKAGE_LIMIT = 80
_FINDING_LIMIT = 40
_RESPONSE_LIMIT = 1_500_000


def normalize_github(value):
    """accept an owner/repo slug or an exact github.com repository URL."""
    if not isinstance(value, str) or len(value) > 300:
        raise source_error('enter a public github owner/repo')
    value = value.strip()
    if value.startswith('https://'):
        parsed = urlsplit(value)
        if (parsed.scheme != 'https' or parsed.netloc.lower() != 'github.com'
                or parsed.query or parsed.fragment):
            raise source_error('use a public github.com repository URL')
        value = parsed.path.strip('/')
    elif '://' in value:
        raise source_error('use a public github.com repository URL')
    if value.endswith('.git'):
        value = value[:-4]
    parts = value.split('/')
    if len(parts) != 2 or any(not _SLUG_PART.fullmatch(part) or part in ('.', '..') for part in parts):
        raise source_error('enter a public github owner/repo')
    return '/'.join(parts)


def normalize_cve(value):
    if not isinstance(value, str):
        raise source_error('enter a cve id')
    value = value.strip().upper()
    match = _CVE_ID.fullmatch(value)
    if not match or int(match.group(1)) < 1999:
        raise source_error('enter a cve id such as CVE-2025-29927')
    return value


async def _fetch_json(client, method, url, *, body=None, missing_ok=False):
    """stream a small json response from an explicitly allowed, redirect-free host."""
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in _ALLOWED_HOSTS or parsed.port not in (None, 443):
        raise source_error('source host is not allowed')
    try:
        async with client.stream(method, url, json=body, follow_redirects=False) as response:
            if missing_ok and response.status_code == 404:
                return None
            if response.status_code >= 300:
                raise source_error(f'{parsed.hostname}: http {response.status_code}')
            if int(response.headers.get('content-length', '0')) > _RESPONSE_LIMIT:
                raise source_error(f'{parsed.hostname}: response too large')
            chunks = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > _RESPONSE_LIMIT:
                    raise source_error(f'{parsed.hostname}: response too large')
                chunks.append(chunk)
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise source_error(f'{parsed.hostname}: source unavailable') from exc
    try:
        return json.loads(b''.join(chunks))
    except (ValueError, UnicodeDecodeError) as exc:
        raise source_error(f'{parsed.hostname}: invalid json') from exc


def _packages_from_lock(payload):
    if not isinstance(payload, dict):
        raise source_error('github: invalid package-lock.json')
    packages = payload.get('packages')
    found = []
    direct = set()
    if isinstance(packages, dict):
        root = packages.get('')
        if isinstance(root, dict):
            for section in ('dependencies', 'devDependencies', 'optionalDependencies'):
                if isinstance(root.get(section), dict):
                    direct.update(root[section])
        for path, item in packages.items():
            if not isinstance(path, str) or not isinstance(item, dict) or 'node_modules/' not in path:
                continue
            name = path.rsplit('node_modules/', 1)[-1]
            version = item.get('version')
            if _NPM_NAME.fullmatch(name) and isinstance(version, str) and _NPM_VERSION.fullmatch(version):
                found.append((name, version, 'npm'))
    else:
        # npm lockfile v1 stores the installed tree under dependencies.
        def walk(dependencies, depth=0):
            if depth > 16 or not isinstance(dependencies, dict):
                return
            for name, item in dependencies.items():
                if not isinstance(name, str) or not isinstance(item, dict):
                    continue
                version = item.get('version')
                if _NPM_NAME.fullmatch(name) and isinstance(version, str) and _NPM_VERSION.fullmatch(version):
                    found.append((name, version, 'npm'))
                walk(item.get('dependencies'), depth + 1)
        walk(payload.get('dependencies'))
    return sorted(set(found), key=lambda package: (package[0] not in direct, package[0], package[1]))


def _packages_from_requirements(contents):
    found = []
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or ';' in line or '\\' in line:
            continue
        line = line.split(' #', 1)[0].strip()
        match = _PYPI_PIN.fullmatch(line)
        if match and '*' not in match.group(2):
            found.append((match.group(1), match.group(2), 'PyPI'))
    return sorted(set(found))


def _decode_manifest(payload, filename):
    if not isinstance(payload, dict) or payload.get('type') != 'file' or payload.get('encoding') != 'base64':
        raise source_error(f'github: {filename} is not a small regular file')
    raw = payload.get('content')
    if not isinstance(raw, str) or len(raw) > _RESPONSE_LIMIT:
        raise source_error(f'github: {filename} is too large')
    try:
        decoded = base64.b64decode(raw, validate=False).decode('utf-8')
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise source_error(f'github: {filename} is not utf-8 text') from exc
    if len(decoded.encode()) > 1_000_000:
        raise source_error(f'github: {filename} is too large')
    return decoded


async def scan_github(value):
    """check up to 80 exact installed versions from one public root manifest against osv."""
    repository = normalize_github(value)
    path = '/'.join(quote(part, safe='') for part in repository.split('/'))
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'oopsie-source-watch/1.0'}
    async with httpx.AsyncClient(timeout=12, headers=headers) as client:
        repo = await _fetch_json(client, 'GET', f'{_GITHUB_BASE}/repos/{path}', missing_ok=True)
        if not isinstance(repo, dict) or repo.get('private') or repo.get('full_name', '').lower() != repository.lower():
            raise source_error('github: public repository not found')
        branch = repo.get('default_branch')
        if not isinstance(branch, str) or not branch or len(branch) > 200:
            raise source_error('github: default branch unavailable')
        commit_data = await _fetch_json(client, 'GET', f'{_GITHUB_BASE}/repos/{path}/commits/{quote(branch, safe="")}')
        commit = commit_data.get('sha') if isinstance(commit_data, dict) else None
        if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
            raise source_error('github: commit unavailable')
        manifest = None
        manifest_payload = None
        for filename in ('package-lock.json', 'requirements.txt'):
            candidate = await _fetch_json(client, 'GET', f'{_GITHUB_BASE}/repos/{path}/contents/{filename}?ref={commit}', missing_ok=True)
            if candidate is not None:
                manifest = filename
                manifest_payload = candidate
                break
        repository_url = f'https://github.com/{repository}'
        checked_at = datetime.now(timezone.utc).isoformat()
        if manifest is None:
            return {'repository': repository, 'manifest': None, 'commit': commit,
                    'dependencies_scanned': 0, 'total_dependencies': 0, 'findings': [],
                    'total_matches': 0, 'source_url': repository_url, 'partial': True,
                    'checked_at': checked_at, 'status': 'unsupported',
                    'note': 'no root package-lock.json or requirements.txt found'}
        manifest_url = f'{repository_url}/blob/{commit}/{manifest}'
        contents = _decode_manifest(manifest_payload, manifest)
        try:
            packages = (_packages_from_lock(json.loads(contents)) if manifest == 'package-lock.json'
                        else _packages_from_requirements(contents))
        except ValueError as exc:
            raise source_error('github: invalid package-lock.json') from exc
        selected = packages[:_PACKAGE_LIMIT]
        findings = []
        total_matches = 0
        paginated = False
        if selected:
            queries = [{'version': version, 'package': {'name': name, 'ecosystem': ecosystem}}
                       for name, version, ecosystem in selected]
            batch = await _fetch_json(client, 'POST', _OSV_BATCH, body={'queries': queries})
            results = batch.get('results') if isinstance(batch, dict) else None
            if not isinstance(results, list) or len(results) != len(selected):
                raise source_error('osv: incomplete query batch')
            for (name, version, ecosystem), result in zip(selected, results):
                if not isinstance(result, dict) or not isinstance(result.get('vulns', []), list):
                    raise source_error('osv: malformed query batch')
                paginated = paginated or bool(result.get('next_page_token'))
                for vulnerability in result.get('vulns', []):
                    vuln_id = vulnerability.get('id') if isinstance(vulnerability, dict) else None
                    if not isinstance(vuln_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{1,100}', vuln_id):
                        continue
                    total_matches += 1
                    if len(findings) < _FINDING_LIMIT:
                        findings.append({'package': name, 'version': version, 'ecosystem': ecosystem,
                                         'id': vuln_id, 'source_url': f'https://osv.dev/vulnerability/{vuln_id}',
                                         'manifest_url': manifest_url})
        partial = len(packages) > len(selected) or paginated or total_matches > len(findings)
        return {'repository': repository, 'manifest': manifest, 'commit': commit,
                'dependencies_scanned': len(selected), 'total_dependencies': len(packages),
                'findings': findings, 'total_matches': total_matches,
                'source_url': manifest_url, 'partial': partial, 'checked_at': checked_at,
                'status': 'partial' if partial else 'checked',
                'note': 'known package-version advisories only; this does not establish exploitability'}


async def scan_cve(value):
    """read an official cve record; never infer whether a caller is affected."""
    cve_id = normalize_cve(value)
    source_url = f'{_CVE_BASE}/{cve_id}'
    async with httpx.AsyncClient(timeout=12, headers={'User-Agent': 'oopsie-source-watch/1.0'}) as client:
        record = await _fetch_json(client, 'GET', source_url, missing_ok=True)
    if not isinstance(record, dict) or record.get('cveMetadata', {}).get('cveId') != cve_id:
        raise source_error('cve: published record not found')
    metadata = record.get('cveMetadata') or {}
    cna = (record.get('containers') or {}).get('cna') or {}
    state = metadata.get('state') if isinstance(metadata.get('state'), str) else 'unknown'
    description = next((item.get('value', '') for item in cna.get('descriptions', [])
                        if isinstance(item, dict) and item.get('lang', '').lower().startswith('en')
                        and isinstance(item.get('value'), str)), '')
    title = cna.get('title') if isinstance(cna.get('title'), str) else ''
    summary = re.sub(r'\s+', ' ', description).strip()[:700]
    title = re.sub(r'\s+', ' ', title).strip()[:180] or (summary.split('. ', 1)[0][:180] if summary else cve_id)
    advisory_url = next((item.get('url') for item in cna.get('references', [])
                         if isinstance(item, dict) and isinstance(item.get('url'), str)
                         and urlsplit(item['url']).scheme == 'https'
                         and urlsplit(item['url']).hostname
                         and ('vendor-advisory' in item.get('tags', [])
                              or '/security/advisories/' in item['url'])), source_url)
    return {'cve_id': cve_id, 'state': state.lower(), 'title': title, 'summary': summary,
            'updated': metadata.get('dateUpdated') or metadata.get('datePublished'),
            'source_url': source_url, 'advisory_url': advisory_url,
            'checked_at': datetime.now(timezone.utc).isoformat(),
            'note': 'official record only; no claim that this workspace is affected'}
