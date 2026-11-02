"""Bounded live teaching scenarios against the fixed local lab brokers only."""
import argparse
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from experiment import Peer, ROOT, envelope
from security import CMD, STATE, EVENT, authenticate, compact, sign
from privacy import pad_envelope
from audit_proof import verify_segment

REPORT = Path('/results/guided-demo.json')
FIXTURE = Path('/results/guided-restart.json')

def save(report):
    temp = REPORT.with_suffix('.tmp')
    temp.write_text(json.dumps(report, indent=2))
    temp.replace(REPORT)

def state(peer, after):
    def latest():
        for topic, wire, received in reversed(peer.messages):
            if topic == STATE and received >= after:
                try:
                    return authenticate(wire, STATE, 'lock', ROOT/'public/lock.pem')['data']
                except ValueError:
                    pass
    with peer.condition:
        peer.condition.wait_for(lambda: latest() is not None, 5)
        result = latest()
    if result is None:
        raise TimeoutError('Fresh signed lock state missing')
    return result

def run(level, report, restart=None):
    profile = 'baseline' if level == 'baseline' else 'hardened'
    full = level == 'hardened'
    def add(scenario, attacker, expected, outcome, **evidence):
        finished = time.time()
        evidence.setdefault('started_epoch', finished - 10)
        evidence['finished_epoch'] = finished
        row = dict(level=level, scenario=scenario, attacker=attacker,
                   expected=expected, outcome=outcome,
                   expectation_met=expected == outcome, **evidence)
        report['rows'].append(row)
        save(report)
        print(compact(row), flush=True)

    if not restart:
        for name, options in [('anonymous', {'anonymous': True}), ('wrong-password', {'bad_password': True})]:
            started = time.time()
            try:
                p = Peer(profile, **options)
                p.close()
                outcome = 'unexpected-connect'
            except PermissionError:
                outcome = 'authentication-rejected'
            add(name, 'Outsider without valid credentials', 'authentication-rejected', outcome, started_epoch=started)

    observer, operator, camera = None, None, None
    try:
        observer = Peer(profile)
        observer.subscribe(EVENT)
        observer.subscribe(STATE)
        operator = Peer(profile)
        camera = Peer(profile, 'camera')
        receipt_segment = []

        def trial(name, attacker, payload, expected, sender=None, before=None):
            before = before or state(observer, time.monotonic())
            started = time.time()
            code, when = (sender or operator).send(CMD, payload)
            decision = observer.decision(payload, when)
            if decision:
                for topic, wire, received in reversed(observer.messages):
                    if topic == EVENT and received >= when:
                        body = authenticate(wire, EVENT, 'lock', ROOT/'public/lock.pem')
                        if body['data']['hash'] == decision['hash']:
                            receipt_segment.append(wire.decode())
                            break
            after = state(observer, time.monotonic())
            outcome = 'broker-rejected' if code >= 128 else decision['reason'] if decision else 'inconclusive'
            delta = after['actions'] - before['actions']
            # No device decision on ACL denial: require fresh signed state and no action.
            if (outcome == 'accepted' and delta != 1) or (outcome != 'accepted' and delta != 0):
                outcome = 'inconclusive'
            add(name, attacker, expected, outcome, puback=code, decision=decision, started_epoch=started,
                before=before, after=after, action_delta=delta,
                payload_sha256=hashlib.sha256(payload.encode()).hexdigest(),
                observation='Signed lock telemetry and signature-verified receipt when available')
            return after

        if restart == 'prepare':
            payload = envelope('LOCK')
            after = trial('restart-original', 'Authorized operator creates the captured fixture', payload, 'accepted')
            FIXTURE.write_text(json.dumps(dict(payload=payload, before=after)))
            return
        if restart == 'check':
            fixture = json.loads(FIXTURE.read_text())
            trial('restart-replay', 'Captured valid envelope and operator MQTT credentials; lock restarted',
                  fixture['payload'], 'replay', before=fixture['before'])
            return

        trial('legitimate-command', 'Authorized operator with signing key', envelope('LOCK'), 'accepted')
        trial('invalid-command', 'Authorized publisher sends invalid business command', envelope('OPEN'), 'command-schema')
        trial('camera-to-lock', 'Camera credentials and camera key only; no operator secrets',
              sign(ROOT/'camera/signing.pem', 'camera', CMD, {'cmd':'UNLOCK'}),
              'accepted' if level == 'baseline' else 'broker-rejected', camera)

        before = state(observer, time.monotonic())
        fake = {'state': 'UNLOCKED' if before['state'] == 'LOCKED' else 'LOCKED', 'actions': 999999}
        forged = sign(ROOT/'camera/signing.pem', 'camera', STATE, fake)
        started = time.time()
        code, when = camera.send(STATE, forged)
        def delivered():
            return any(t == STATE and p.decode() == forged and ts >= when for t,p,ts in observer.messages)
        with observer.condition:
            observer.condition.wait_for(delivered, 2)
            seen = delivered()
        after = state(observer, time.monotonic())
        outcome = 'broker-rejected' if code >= 128 and not seen else 'forged-state-delivered' if seen else 'inconclusive'
        if after['actions'] != before['actions']:
            outcome = 'inconclusive'
        add('camera-state-forgery', 'Camera credentials and camera key; forged message targets lock state',
            'forged-state-delivered' if level == 'baseline' else 'broker-rejected', outcome,
            puback=code, forged_value=fake, delivered=seen, before=before, after=after, started_epoch=started,
            action_delta=after['actions']-before['actions'],
            observation='Exact forged payload observed on MQTT; actual lock state verified independently',
            payload_sha256=hashlib.sha256(forged.encode()).hexdigest())

        # A schema-valid forgery with no usable signature: operator password alone is insufficient.
        unsigned = json.loads(envelope())
        unsigned['sig'] = ''
        trial('stolen-operator-password', 'Operator MQTT credentials only; no signing key', compact(unsigned),
              'bad-signature' if full else 'accepted')
        captured = envelope('LOCK')
        trial('replay-original', 'Authorized operator creates the captured fixture', captured, 'accepted')
        trial('replay-copy', 'Captured valid envelope plus authorized MQTT publishing access; no signing key',
              captured, 'replay' if full else 'accepted')

        original = json.loads(envelope('LOCK'))
        body = json.loads(original['msg'])
        body['data']['cmd'] = 'UNLOCK'
        original['msg'] = compact(body)
        trial('modified-payload', 'Enrolled publisher changes a captured command while keeping its original signature; application tampering, not TLS MITM',
              compact(original), 'bad-signature' if full else 'accepted')

        # Demonstrate historical evidence tampering without touching live SQLite data.
        audit_start = time.time()
        anchor = json.loads(json.loads(receipt_segment[-1])['msg'])['data']
        anchor = {k: anchor[k] for k in ('n', 'hash')}
        intact = verify_segment(receipt_segment, ROOT/'public/lock.pem', anchor)
        altered = list(receipt_segment)
        outer = json.loads(altered[-1])
        modified = json.loads(outer['msg'])
        modified['data']['state'] = 'FALSE-STATE'
        outer['msg'] = compact(modified)
        altered[-1] = compact(outer)
        rejected = []
        for candidate in (altered, receipt_segment[:-1]):
            try:
                verify_segment(candidate, ROOT/'public/lock.pem', anchor)
                rejected.append(False)
            except ValueError:
                rejected.append(True)
        add('audit-proof', 'Denial or editing/truncation of exported evidence; no signing-key compromise',
            'tampering-detected', 'tampering-detected' if intact and all(rejected) else 'inconclusive',
            started_epoch=audit_start, network_evidence_required=False,
            anchor=anchor, signed_receipts=list(receipt_segment), original_verified=intact,
            modification_detected=rejected[0], truncation_detected=rejected[1],
            observation='Baseline also has signed observer instrumentation; it does not verify command authorship. Key attribution is not proof of a human actor.')

        time.sleep(2.1)
        before = state(observer, time.monotonic())
        started = time.time()
        batch = []
        for i in range(12):
            payload = envelope('LOCK' if i % 2 else 'UNLOCK')
            code, when = operator.send(CMD, payload)
            batch.append((payload, code, when))
            time.sleep(0.05)
        decisions = [observer.decision(payload, when) for payload, _, when in batch]
        after = state(observer, time.monotonic())
        accepted = sum(bool(d and d['accepted']) for d in decisions)
        limited = sum(bool(d and d['reason'] == 'command-rate') for d in decisions)
        complete = all(d is not None for d in decisions) and after['actions'] - before['actions'] == accepted
        expected = 'rate-limited' if full else 'all-accepted'
        outcome = ('rate-limited' if 0 < accepted <= 5 and limited >= 7 else 'all-accepted' if accepted == 12 else 'inconclusive') if complete else 'inconclusive'
        add('bounded-command-burst', 'Compromised authorized automation with operator key; 12 commands at 50 ms requested intervals',
            expected, outcome, started_epoch=started, before=before, after=after,
            action_delta=after['actions']-before['actions'], accepted=accepted, rate_rejected=limited, decisions=decisions)
        time.sleep(2.1)
        trial('post-burst-recovery', 'Legitimate operator after bounded pressure', envelope('LOCK'), 'accepted')

        # Bounded capacity test, not an Internet-scale flood. Existing legitimate peers stay connected.
        started = time.time()
        def connect_probe(_):
            try:
                return Peer(profile, 'camera')
            except (OSError, TimeoutError, PermissionError):
                return None
        probes = []
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                probes = list(pool.map(connect_probe, range(52)))
            admitted = sum(p is not None for p in probes)
            add('connection-pressure', 'Enrolled camera credential opens up to 52 sessions, eight connection attempts at a time',
                'connections-bounded', 'connections-bounded' if 0 < admitted < 50 else 'inconclusive',
                started_epoch=started, attempted=52, admitted=admitted, refused_or_timed_out=52-admitted,
                observation='Both profiles have a 50-connection cap. This checks bounded admission, not per-IP fairness or complete DoS prevention.')
        finally:
            for peer in probes:
                if peer:
                    peer.close()
        trial('post-connection-recovery', 'Legitimate operator after bounded connection pressure', envelope('LOCK'), 'accepted')

        # Same synthetic occupancy labels; full privacy uses fixed cadence and padding.
        windows = []
        started = time.time()
        source_port = camera.c.socket().getsockname()[1]
        for occupied in (False, True, True, False, True, False, False, True):
            start_epoch = time.time()
            deadline = time.monotonic() + 1.2
            count = 4 if full or occupied else 1
            for i in range(count):
                payload = sign(ROOT/'camera/signing.pem', 'camera', 'home/frontdoor/camera/status', {'status':'ONLINE','motion':occupied})
                if full:
                    payload = pad_envelope(payload)
                camera.send('home/frontdoor/camera/status', payload)
                time.sleep(max(0, deadline - (count - i - 1) * 0.3 - time.monotonic()) if i == count - 1 else 0.3)
            windows.append(dict(start=start_epoch, end=time.time(), occupied=occupied, sent=count))
        add('traffic-analysis', 'Passive observer uses encrypted TCP payload volume to infer synthetic camera activity',
            'recorded-for-analysis', 'recorded-for-analysis', started_epoch=started,
            privacy_windows=windows, source_port=source_port,
            observation='First four labeled windows train a byte-volume threshold; last four test it. Small controlled demonstration, not a real-home accuracy claim.')
    finally:
        for peer in (camera, operator, observer):
            if peer:
                peer.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--level', choices=['baseline', 'intermediate', 'hardened'])
    parser.add_argument('--stage', choices=['start', 'finish', 'abort'])
    parser.add_argument('--restart', choices=['prepare', 'check'])
    parser.add_argument('--run-id')
    args = parser.parse_args()
    if args.stage == 'start':
        if not args.run_id or not all(c.isalnum() or c == '-' for c in args.run_id):
            parser.error('--stage start requires an alphanumeric --run-id')
        save(dict(schema=1, run_id=args.run_id, packet_analysis={'status': 'pending'}, created_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                  status='running', rows=[], error=None, controls_restored=False))
        (Path('/results/captures')/args.run_id/'lock-public.pem').write_bytes((ROOT/'public/lock.pem').read_bytes())
        return
    report = json.loads(REPORT.read_text())
    if args.stage:
        report['controls_restored'] = True  # Orchestrator calls only after restoring and checking full policy.
        report['status'] = 'complete' if args.stage == 'finish' else 'failed'
        proofs = [r for r in report['rows'] if r['scenario'] == 'audit-proof']
        try:
            report['audit_proofs_verified'] = len(proofs) == 3 and all(
                verify_segment(r['signed_receipts'], ROOT/'public/lock.pem', r['anchor']) for r in proofs)
        except (ValueError, KeyError) as exc:
            report['audit_proofs_verified'] = False
            report['error'] = f'Archived proof verification failed: {exc}'
            report['status'] = 'failed'
        report['device_expectations_met'] = (args.stage == 'finish' and report['audit_proofs_verified'] and len(report['rows']) == 50
                                           and all(r['expectation_met'] for r in report['rows']))
        report['all_expectations_met'] = False  # Only offline packet analysis can finish verification.
        save(report)
        return
    try:
        run(args.level, report, args.restart)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        report['status'] = 'failed'
        save(report)
        raise
    if any(not r['expectation_met'] for r in report['rows']):
        raise SystemExit('Unexpected outcome; inspect the recorded evidence.')

if __name__ == '__main__':
    main()
