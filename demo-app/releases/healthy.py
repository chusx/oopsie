def handle(tenant, invoice_id, invoices):
    if not tenant:
        return 401, {'error': 'auth required'}
    invoice = invoices.get(invoice_id)
    if not invoice or invoice['tenant_id'] != tenant:
        return 403, {'error': 'nope: tenant boundary'}
    return 200, {'id': invoice_id, 'amount_minor': invoice['amount_minor'], 'currency': invoice['currency']}
