"""Bounded, owner-verified HTTPS contract checks for public endpoints."""
import asyncio
import hashlib
import ipaddress
import os
import re
import socket
import tempfile
from urllib.parse import urlsplit, urlunsplit

from .config import local


class url_watch_error(Exception):
    pass


def normalize_url(value):
    if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 33 or c == '\\' for c in value):
        raise url_watch_error('enter a public https url without spaces or credentials')
    parts = urlsplit(value)
    host = parts.hostname
    if parts.scheme != 'https' or not host or parts.username or parts.password or parts.fragment or parts.query:
        raise url_watch_error('enter a public https url without credentials, queries, or fragments')
    host = host.lower()
    if parts.netloc.lower() != host or len(host) > 253 or not re.fullmatch(r'[a-z0-9.-]+', host):
        raise url_watch_error('use a dns hostname on the standard https port')
    if host.endswith('.') or '..' in host or '.' not in host or any(not label or len(label) > 63 or label[0] == '-' or label[-1] == '-' for label in host.split('.')):
        raise url_watch_error('enter a valid public dns hostname')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise url_watch_error('ip literals cannot be watched')
    if host in {'localhost', 'localhost.localdomain'} or host.endswith(('.localhost', '.local', '.internal')):
        raise url_watch_error('private hostnames cannot be watched')
    return urlunsplit(('https', host, parts.path or '/', parts.query, ''))


def verification_record(url):
    return '_oopsie-challenge.' + urlsplit(normalize_url(url)).hostname


def txt_has_token(output, token):
    expected = 'oopsie=' + token
    return any(line.strip().strip('"') == expected for line in output.splitlines())


async def verify_dns(url, token):
    record = verification_record(url)
    proc = await asyncio.create_subprocess_exec('dig', '+short', '+time=2', '+tries=1', 'TXT', record,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), 5)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        raise url_watch_error('dns verification timed out')
    if proc.returncode != 0:
        raise url_watch_error('dns verification unavailable')
    return txt_has_token(out.decode('utf-8', errors='replace'), token)


def global_ipv4(addresses):
    ips = [item[4][0] for item in addresses]
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise url_watch_error('url resolves to a private or reserved address')
    return ips[0]


async def pinned_ipv4(host):
    try:
        answers = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, 443, socket.AF_INET, socket.SOCK_STREAM), 4)
    except (asyncio.TimeoutError, OSError):
        raise url_watch_error('public dns lookup failed')
    return global_ipv4(answers)


def validate_contract(expected_status=200, marker=''):
    if not isinstance(expected_status, int) or not 100 <= expected_status <= 599:
        raise url_watch_error('expected status must be an http code')
    if not isinstance(marker, str) or len(marker) > 100 or any(ord(c) < 32 for c in marker):
        raise url_watch_error('expected text must be a short, nonsecret phrase')
    return expected_status, marker


async def scan_url(url, expected_status=200, marker=''):
    """Make one GET to a DNS-pinned public IPv4; never follow redirects or keep body bytes."""
    url = normalize_url(url)
    validate_contract(expected_status, marker)
    host = urlsplit(url).hostname
    ip = await pinned_ipv4(host)
    fd, path = tempfile.mkstemp(prefix='url-watch-', dir=local)
    os.close(fd)
    try:
        proc = await asyncio.create_subprocess_exec('/usr/bin/curl', '--disable', '--silent', '--show-error', '--http1.1',
            '--noproxy', '*', '--proto', '=https', '--max-time', '8', '--connect-timeout', '3',
            '--max-filesize', '65536', '--resolve', f'{host}:443:{ip}', '--output', path,
            '--write-out', '%{http_code}', '--', url,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent'})
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), 10)
        except asyncio.TimeoutError:
            proc.kill(); await proc.wait()
            raise url_watch_error('https check timed out')
        if proc.returncode != 0:
            raise url_watch_error('https check failed or response exceeded 64 kb')
        status = int(out.decode('ascii').strip())
        with open(path, 'rb') as handle:
            body = handle.read(65537)
        if len(body) > 65536:
            raise url_watch_error('response exceeded 64 kb')
        matched = marker in body.decode('utf-8', errors='replace') if marker else None
        passed = status == expected_status and (matched is None or matched)
        return {'status': status, 'expected_status': expected_status, 'marker_matched': matched,
            'passed': bool(passed), 'body_sha256': hashlib.sha256(body).hexdigest(),
            'source_url': url, 'redirects_followed': False}
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
