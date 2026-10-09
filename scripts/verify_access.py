"""Read credentials locally and report only redacted, read-only access checks."""
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


def read_credentials(path):
    credentials = {}
    for line in path.read_text().splitlines():
        if ':' in line:
            label, value = line.split(':', 1)
            credentials[label.strip().lower()] = value.strip()
    pair = credentials.get('clickhouse', '').split()
    if len(pair) == 2:
        credentials.setdefault('clickhouse key id', pair[0])
        credentials.setdefault('clickhouse key secret', pair[1])
    return credentials


def check(label, url, headers):
    headers = {**headers, 'User-Agent': 'Oopsie-access-check/1.0'}
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1_000_000)
            status = response.status
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            body = None
        result = {'vendor': label, 'http_status': status}
        if isinstance(body, dict):
            result['json_response'] = True
            if label == 'AkashML' and isinstance(body.get('data'), list):
                result['model_count'] = len(body['data'])
            if label == 'Guild' and isinstance(body.get('scopes'), list):
                result['scopes'] = body['scopes']
        return result
    except urllib.error.HTTPError as exc:
        return {'vendor': label, 'http_status': exc.code}
    except Exception as exc:
        return {'vendor': label, 'error_type': type(exc).__name__}


def main():
    path = os.getenv('OOPSIE_CREDENTIAL_FILE')
    if not path or not Path(path).is_file():
        raise SystemExit('set OOPSIE_CREDENTIAL_FILE to a private credential file')
    credentials = read_credentials(Path(path))
    if 'elvenlabs' in credentials:
        credentials.setdefault('elevenlabs', credentials['elvenlabs'])
    jobs = []
    definitions = [
        ('akashml', 'AkashML', 'https://api.akashml.com/v1/models', 'Authorization'),
        ('senso', 'Senso', 'https://apiv2.senso.ai/api/v1/org/me', 'X-API-Key'),
        ('guild.ai', 'Guild', 'https://api.guild.ai/v1/me', 'Authorization'),
        ('semgrep web', 'Semgrep web', 'https://semgrep.dev/api/v1/deployments', 'Authorization'),
        ('semgrep ci', 'Semgrep CI', 'https://semgrep.dev/api/agent/deployments/current', 'Authorization'),
        ('elevenlabs', 'ElevenLabs', 'https://api.elevenlabs.io/v1/user', 'xi-api-key'),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        for field, label, url, header in definitions:
            value = credentials.get(field)
            if not value:
                print(json.dumps({'vendor': label, 'status': 'credential missing'}))
                continue
            if field.startswith('semgrep'):
                # Accept a supplied 'Bearer token' or a token alone.
                value = value.removeprefix('Bearer ').removeprefix('bearer ')
                # A token label may precede the secret in the handoff file.
                if len(value.split()) == 2:
                    value = max(value.split(), key=len)
            if field == 'guild.ai':
                auth = 'Basic ' + base64.b64encode(value.encode()).decode()
            elif header == 'Authorization':
                auth = 'Bearer ' + value
            else:
                auth = value
            jobs.append(pool.submit(check, label, url, {header: auth, 'Accept': 'application/json'}))
        for job in jobs:
            print(json.dumps(job.result()))
    clickhouse_url = os.environ.get('CLICKHOUSE_URL') or credentials.get('clickhouse url')
    if clickhouse_url and credentials.get('clickhouse'):
        user = os.environ.get('CLICKHOUSE_USER') or credentials.get('clickhouse user', 'default')
        auth = base64.b64encode((user + ':' + credentials['clickhouse']).encode()).decode()
        print(json.dumps(check('ClickHouse', clickhouse_url.rstrip('/') + '/?query=SELECT%201', {'Authorization': 'Basic ' + auth})))
    elif credentials.get('clickhouse key id') and (credentials.get('clickhouse key secret') or credentials.get('clickhouse')):
        pair = credentials['clickhouse key id'] + ':' + (credentials.get('clickhouse key secret') or credentials['clickhouse'])
        auth = base64.b64encode(pair.encode()).decode()
        print(json.dumps(check('ClickHouse Cloud API', 'https://api.clickhouse.cloud/v1/organizations', {'Authorization': 'Basic ' + auth})))
    else:
        print(json.dumps({'vendor': 'ClickHouse', 'status': 'single value present; Cloud provisioning needs key ID and key secret'}))
    for field in ['openai', 'mongodb', 'elevenlabs']:
        if field not in credentials:
            print(json.dumps({'vendor': field, 'status': 'not in credential file'}))


if __name__ == '__main__':
    main()
