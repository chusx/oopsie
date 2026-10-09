"""Custom URL checks must never become a host-network proxy."""
import socket
import pytest
from worker.realworld_urls import normalize_url, global_ipv4, txt_has_token, url_watch_error


@pytest.mark.parametrize('value', [
    'http://example.com/', 'https://127.0.0.1/', 'https://localhost/',
    'https://example.com:8443/', 'https://user:pass@example.com/',
    'https://example.com/\nadmin', 'https://example.com\\@127.0.0.1/',
    'https://example.com/#fragment', 'https://example.com/health?token=secret',
    'https://service.internal/health',
])
def test_url_validation_rejects_unsafe_targets(value):
    with pytest.raises(url_watch_error):
        normalize_url(value)


def test_url_validation_and_dns_pin_only_global_addresses():
    assert normalize_url('https://Example.COM/health') == 'https://example.com/health'
    public = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 443))]
    private = public + [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 443))]
    assert global_ipv4(public) == '93.184.215.14'
    with pytest.raises(url_watch_error, match='private or reserved'):
        global_ipv4(private)


def test_dns_ownership_token_requires_exact_txt_value():
    assert txt_has_token('"oopsie=abc123"\n"other=value"', 'abc123')
    assert not txt_has_token('"oopsie=abc123-extra"', 'abc123')
