"""Verify historical signed receipt segments against a separately retained anchor."""
import hashlib
import json
from security import EVENT, authenticate, compact

def verify_segment(receipts, public_path, anchor):
    previous = None
    for wire in receipts:
        # Historical proof checks authenticity at signing time, not present freshness.
        timestamp = json.loads(json.loads(wire)['msg'])['ts']
        event = authenticate(wire, EVENT, 'lock', public_path, now=timestamp)['data']
        body = {k: v for k, v in event.items() if k != 'hash'}
        if hashlib.sha256(compact(body).encode()).hexdigest() != event['hash']:
            raise ValueError('audit-hash-mismatch')
        if previous and (event['n'] != previous['n'] + 1 or event['previous'] != previous['hash']):
            raise ValueError('audit-chain-gap')
        previous = event
    if previous is None or (previous['n'], previous['hash']) != (anchor['n'], anchor['hash']):
        raise ValueError('audit-anchor-mismatch')
    return True

if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description='Verify archived receipt segments using only the lock public key.')
    parser.add_argument('report')
    parser.add_argument('public_key')
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text())
    proofs = [r for r in report['rows'] if r['scenario'] == 'audit-proof']
    if not proofs:
        raise SystemExit('No audit proofs in report')
    for proof in proofs:
        verify_segment(proof['signed_receipts'], args.public_key, proof['anchor'])
        print(f"{proof['level']}: signed receipt segment verifies against its saved anchor")
    print('Trust requires an independently retained anchor/public key; this does not prove human identity.')
