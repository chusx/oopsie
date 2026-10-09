import json
from handler import handle

invoices = {
    'inv_a': {'tenant_id': 'a', 'amount_minor': 1299, 'currency': 'usd'},
    'inv_b': {'tenant_id': 'b', 'amount_minor': 4200, 'currency': 'usd'},
}
checks = [
    ('amount and current schema', 'a', 'inv_a', 200, {'id': 'inv_a', 'amount_minor': 1299, 'currency': 'usd'}),
    ('tenant boundary', 'a', 'inv_b', 403, {'error': 'nope: tenant boundary'}),
    ('positive access for b', 'b', 'inv_b', 200, {'id': 'inv_b', 'amount_minor': 4200, 'currency': 'usd'}),
    ('unauthenticated denial', None, 'inv_a', 401, {'error': 'auth required'}),
    ('unknown invoice denial', 'a', 'missing', 403, {'error': 'nope: tenant boundary'}),
]
results=[]
for name, tenant, invoice, expected_status, expected_body in checks:
    try:
        status, body = handle(tenant, invoice, invoices)
        passed = status == expected_status and body == expected_body and invoices['inv_a']['amount_minor'] == 1299
        results.append({'name': name, 'passed': passed, 'status': status, 'expected': expected_body, 'observed': body})
    except Exception as exc:
        results.append({'name': name, 'passed': False, 'error': type(exc).__name__})
print(json.dumps(results))
