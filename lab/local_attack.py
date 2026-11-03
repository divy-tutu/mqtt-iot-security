"""One-at-a-time attacks against only the fixed Docker lab brokers."""
import argparse
import json
import time
from pathlib import Path

from audit_proof import verify_segment
from experiment import Peer, ROOT, envelope
from privacy import pad_envelope
from security import CMD, EVENT, compact, sign, authenticate

REPORT = Path('/results/latest-local-attack.json')
TITLES = {
    'unauthorized-access': 'Unauthorized access',
    'traffic-analysis': 'Traffic analysis',
    'stolen-credential': 'Stolen operator credential',
    'camera-injection': 'Camera-to-lock injection',
    'modification': 'Payload modification',
    'replay': 'Replay',
    'evidence-tampering': 'Evidence tampering',
    'availability-pressure': 'Availability pressure',
}


def save(report):
    REPORT.parent.mkdir(exist_ok=True)
    temporary = REPORT.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2))
    temporary.replace(REPORT)


def prepare(observer, operator):
    for attempt in range(2):
        payload = envelope('LOCK')
        code, when = operator.send(CMD, payload)
        decision = observer.decision(payload, when)
        if code < 128 and decision and decision.get('accepted'):
            return decision
        if attempt == 0 and decision and decision.get('reason') == 'command-rate':
            time.sleep(2.1)
            continue
        raise RuntimeError('could not place the lock in a known state')


def trial(observer, sender, payload, before):
    code, when = sender.send(CMD, payload)
    decision = observer.decision(payload, when)
    outcome = 'broker-rejected' if code >= 128 else decision['reason'] if decision else 'inconclusive'
    after = ({'state': decision['state'], 'actions': decision['actions']} if decision else
             {'state': before['state'], 'actions': before['actions']})
    return dict(outcome=outcome, puback=code, before={'state':before['state'], 'actions':before['actions']},
                after=after, action_delta=after['actions']-before['actions'])


def unauthorized(profile):
    outcomes = []
    for name, options in [('anonymous', {'anonymous':True}), ('wrong-password', {'bad_password':True})]:
        try:
            peer = Peer(profile, **options)
            peer.close()
            outcome = 'unexpected-connect'
        except PermissionError:
            outcome = 'authentication-rejected'
        outcomes.append({'attempt':name, 'outcome':outcome})
    return dict(profile=profile, outcome='authentication-rejected' if all(x['outcome'] == 'authentication-rejected' for x in outcomes) else 'inconclusive',
                attacker='outsider without a valid MQTT password', attempts=outcomes,
                parameters={'attempts':2, 'anonymous':True, 'wrong_password':True})


def traffic_analysis(profile):
    protected = profile == 'hardened'
    camera = Peer(profile, 'camera')
    labels = [False, True, True, False, True, False, False, True]
    counts = []
    try:
        for occupied in labels:
            count = 4 if protected or occupied else 1
            deadline = time.monotonic() + 1.2
            for index in range(count):
                payload = sign(ROOT/'camera/signing.pem', 'camera', 'home/frontdoor/camera/status',
                               {'status':'ONLINE', 'motion':occupied})
                if protected:
                    payload = pad_envelope(payload)
                camera.send('home/frontdoor/camera/status', payload)
                if index < count - 1:
                    time.sleep(.3)
            time.sleep(max(0, deadline-time.monotonic()))
            counts.append(count)
    finally:
        camera.close()
    idle = sum(value for value, occupied in zip(counts[:4], labels[:4]) if not occupied) / 2
    active = sum(value for value, occupied in zip(counts[:4], labels[:4]) if occupied) / 2
    distinguishable = active != idle
    threshold = (active+idle)/2
    predictions = [(value > threshold) if distinguishable else False for value in counts[4:]]
    accuracy = sum(prediction == truth for prediction, truth in zip(predictions, labels[4:])) / 4
    return dict(profile=profile, outcome='inference-reduced' if accuracy <= .5 else 'activity-inferred',
                attacker='passive observer comparing camera traffic volume', sent_per_window=counts,
                inference_accuracy=accuracy,
                parameters={'windows':8, 'window_seconds':1.2, 'training_windows':4, 'test_windows':4,
                            'hardened_envelope_bytes':1024, 'hardened_interval_seconds':.5})


def command_attack(profile, scenario):
    observer = Peer(profile)
    operator = Peer(profile)
    camera = Peer(profile, 'camera') if scenario == 'camera-injection' else None
    observer.subscribe(EVENT)
    try:
        before = prepare(observer, operator)
        if scenario == 'camera-injection':
            payload = sign(ROOT/'camera/signing.pem', 'camera', CMD, {'cmd':'UNLOCK'})
            result = trial(observer, camera, payload, before)
            result.update(attacker='camera MQTT password and camera signing key; no operator secret',
                          parameters={'identity':'camera', 'topic':CMD, 'command':'UNLOCK', 'qos':1})
        elif scenario == 'stolen-credential':
            outer = json.loads(envelope('UNLOCK')); outer['sig'] = ''
            result = trial(observer, operator, compact(outer), before)
            result.update(attacker='operator MQTT password without the operator signing key',
                          parameters={'topic':CMD, 'command':'UNLOCK', 'signature':'empty', 'qos':1})
        elif scenario == 'modification':
            outer = json.loads(envelope('LOCK')); body = json.loads(outer['msg'])
            body['data']['cmd'] = 'UNLOCK'; outer['msg'] = compact(body)
            result = trial(observer, operator, compact(outer), before)
            result.update(attacker='authorized publisher editing a captured signed command',
                          parameters={'topic':CMD, 'original':'LOCK', 'modified':'UNLOCK',
                                      'signature':'original retained', 'qos':1})
        elif scenario == 'replay':
            payload = envelope('UNLOCK')
            first = trial(observer, operator, payload, before)
            second_before = first['after']
            second = trial(observer, operator, payload, second_before)
            result = dict(profile=profile, outcome=second['outcome'], pubacks=[first['puback'], second['puback']],
                          before=first['before'], after=second['after'],
                          action_delta=second['after']['actions']-first['before']['actions'],
                          first_outcome=first['outcome'], second_outcome=second['outcome'],
                          attacker='captured valid signed envelope and authorized publish access',
                          parameters={'copies':2, 'same_command_id':True, 'freshness_window_seconds':30, 'qos':1})
            return result
        elif scenario == 'availability-pressure':
            time.sleep(2.1)
            batch = []
            for index in range(12):
                payload = envelope('UNLOCK' if index % 2 == 0 else 'LOCK')
                code, when = operator.send(CMD, payload)
                batch.append((payload, code, when))
                time.sleep(.05)
            decisions = [observer.decision(payload, when) for payload, _, when in batch]
            accepted = sum(bool(item and item.get('accepted')) for item in decisions)
            limited = sum(bool(item and item.get('reason') == 'command-rate') for item in decisions)
            last = next(item for item in reversed(decisions) if item)
            result = dict(outcome='rate-limited' if limited else 'all-accepted', puback=max(code for _, code, _ in batch),
                          before={'state':before['state'], 'actions':before['actions']},
                          after={'state':last['state'], 'actions':last['actions']},
                          action_delta=last['actions']-before['actions'], accepted=accepted, rate_rejected=limited,
                          attacker='authorized automation with operator credential and signing key',
                          parameters={'commands':12, 'requested_interval_ms':50, 'unique_ids':12, 'qos':1})
        else:
            receipts = []
            current = before
            for command in ('UNLOCK', 'LOCK', 'UNLOCK'):
                payload = envelope(command)
                code, when = operator.send(CMD, payload)
                decision = observer.decision(payload, when)
                if code >= 128 or not decision:
                    raise RuntimeError('receipt fixture command failed')
                for topic, wire, received in reversed(observer.messages):
                    if topic == EVENT and received >= when:
                        data = authenticate(wire, EVENT, 'lock', ROOT/'public/lock.pem')['data']
                        if data['hash'] == decision['hash']:
                            receipts.append(wire.decode()); break
                current = decision
            anchor_data = json.loads(json.loads(receipts[-1])['msg'])['data']
            anchor = {key:anchor_data[key] for key in ('n','hash')}
            intact = verify_segment(receipts, ROOT/'public/lock.pem', anchor)
            altered = list(receipts); outer = json.loads(altered[-1]); body = json.loads(outer['msg'])
            body['data']['state'] = 'FALSE-STATE'; outer['msg'] = compact(body); altered[-1] = compact(outer)
            detected = []
            for candidate in (altered, receipts[:-1]):
                try:
                    verify_segment(candidate, ROOT/'public/lock.pem', anchor); detected.append(False)
                except ValueError:
                    detected.append(True)
            result = dict(outcome='tampering-detected' if intact and all(detected) else 'inconclusive',
                          before={'state':before['state'], 'actions':before['actions']},
                          after={'state':current['state'], 'actions':current['actions']},
                          action_delta=current['actions']-before['actions'], modification_detected=detected[0],
                          truncation_detected=detected[1], attacker='editor of exported receipt copies; no signing key',
                          parameters={'receipts':3, 'tests':'one modified copy and one truncated copy'})
        result['profile'] = profile
        return result
    finally:
        if camera: camera.close()
        operator.close(); observer.close()


def run_profile(profile, scenario):
    if scenario == 'unauthorized-access': return unauthorized(profile)
    if scenario == 'traffic-analysis': return traffic_analysis(profile)
    return command_attack(profile, scenario)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenario', required=True, choices=sorted(TITLES))
    args = parser.parse_args()
    report = {'schema':1, 'scenario':args.scenario, 'title':TITLES[args.scenario],
              'created_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'status':'running', 'results':[], 'error':None}
    save(report)
    try:
        for profile in ('baseline','hardened'):
            result = run_profile(profile, args.scenario)
            report['results'].append(result); save(report)
            print(compact(result), flush=True)
        report['status'] = 'complete'
    except Exception as exc:
        report['status'] = 'failed'; report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        save(report)


if __name__ == '__main__':
    main()
