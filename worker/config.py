import hashlib
import json
import os
import secrets
from pathlib import Path
from scripts.verify_access import read_credentials

root = Path(__file__).resolve().parents[1]
local = root / '.local'
local.mkdir(exist_ok=True)
credential_file = os.getenv('OOPSIE_CREDENTIAL_FILE')
credentials = read_credentials(Path(credential_file)) if credential_file and Path(credential_file).is_file() else {}
credentials['elevenlabs'] = credentials.get('elevenlabs') or credentials.get('elvenlabs', '')

def key(label, env):
    return os.getenv(env) or credentials.get(label, '')

def runtime():
    path = local / 'runtime.json'
    return json.loads(path.read_text()) if path.exists() else {}

def save_runtime(update):
    data = runtime() | update
    path = local / 'runtime.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(data, out)
    return data

if not runtime().get('worker_key'):
    save_runtime({'worker_key': secrets.token_urlsafe(40)})

def digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()

public_app = os.getenv('OOPSIE_APP_URL', 'https://app.oopsie.website')
public_api = os.getenv('OOPSIE_API_URL', 'https://api.oopsie.website')
