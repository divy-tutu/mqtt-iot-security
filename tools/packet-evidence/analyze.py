"""Offline PyShark evidence. Never decrypt TLS or print captured passwords."""
import hashlib
import json
from pathlib import Path

import pyshark


def analyze(path, rows, encrypted, root=Path('/results')):
    result = dict(file=path.relative_to(root).as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  packets=0, mqtt_packets=0, tls_packets=0, tls_data_packets=0,
                  readable_publishes=0, credential_packets=0)
    matches = {i: [] for i in range(len(rows))}
    windows = {i: 0 for i in range(len(rows))}
    privacy = {i: [0] * len(row['privacy_windows']) for i, row in enumerate(rows) if 'privacy_windows' in row}
    capture = pyshark.FileCapture(str(path), keep_packets=False,
                                 decode_as={'tcp.port==8883': 'tls'})
    try:
        for packet in capture:
            result['packets'] += 1
            ts = float(packet.sniff_timestamp)
            layers = packet.layers
            mqtt = [layer for layer in layers if layer.layer_name == 'mqtt']
            tls = [layer for layer in layers if layer.layer_name == 'tls']
            result['mqtt_packets'] += bool(mqtt)
            result['tls_packets'] += bool(tls)
            result['tls_data_packets'] += any(hasattr(layer, 'app_data') for layer in tls)
            for i, row in enumerate(rows):
                if row['started_epoch'] <= ts <= row['finished_epoch']:
                    windows[i] += 1
                if i in privacy and hasattr(packet, 'tcp') and int(packet.tcp.srcport) == row['source_port']:
                    for j, window in enumerate(row['privacy_windows']):
                        if window['start'] <= ts < window['end']:
                            privacy[i][j] += int(packet.tcp.len)
            for layer in mqtt:
                result['credential_packets'] += bool(getattr(layer, 'username', None) or getattr(layer, 'passwd', None))
                if not hasattr(layer, 'msg'):
                    continue
                # PDML may contain several MQTT PUBLISH messages in one TCP packet.
                for field in layer.msg.all_fields:
                    payload = bytes.fromhex(str(field.show).replace(':', ''))
                    result['readable_publishes'] += 1
                    digest = hashlib.sha256(payload).hexdigest()
                    for i, row in enumerate(rows):
                        if (digest == row.get('payload_sha256') and
                                row['started_epoch'] <= ts <= row['finished_epoch']):
                            matches[i].append(int(packet.number))
    finally:
        capture.close()
    result['expectation_met'] = (result['tls_data_packets'] > 0 and result['mqtt_packets'] == 0
                                 if encrypted else result['readable_publishes'] > 0)
    for i, row in enumerate(rows):
        row['packet_evidence'] = dict(file=result['file'], window_packets=windows[i],
            matching_payload_frames=matches[i],
            correlation='time-window-only; TLS payload not decrypted' if encrypted else 'payload SHA-256 and time window')
        if row.get('network_evidence_required', True) and (windows[i] == 0 or (not encrypted and row.get('payload_sha256') and not matches[i])):
            result['expectation_met'] = False
        if i in privacy:
            values = privacy[i]
            labels = [w['occupied'] for w in row['privacy_windows']]
            idle = sum(v for v, occupied in zip(values[:4], labels[:4]) if not occupied) / 2
            active = sum(v for v, occupied in zip(values[:4], labels[:4]) if occupied) / 2
            threshold = (idle + active) / 2
            distinguishable = abs(active - idle) > max(active, idle) * 0.1
            predictions = [(v > threshold if active >= idle else v < threshold) if distinguishable else False for v in values[4:]]
            accuracy = sum(p == truth for p, truth in zip(predictions, labels[4:])) / 4
            row['privacy_measurement'] = dict(tcp_payload_bytes=values, test_accuracy=accuracy,
                training_windows=4, test_windows=4, threshold_bytes=threshold, predictions=predictions,
                interpretation='Controlled synthetic workload only; other flows, reconnects and commands still expose metadata.')
            row['expected'] = 'inference-reduced' if row['level'] == 'hardened' else 'activity-inferred'
            row['outcome'] = 'inference-reduced' if accuracy <= 0.5 else 'activity-inferred' if accuracy >= 0.75 else 'inconclusive'
            row['expectation_met'] = min(values) > 0 and row['expected'] == row['outcome']
            if not row['expectation_met']:
                result['expectation_met'] = False
    return result


def main():
    report_path = Path('/results/guided-demo.json')
    report = json.loads(report_path.read_text())
    directory = Path('/results/captures') / report['run_id']
    evidence = dict(status='failed', captures=[], error=None,
                    interpretation='TLS visibility proves transport confidentiality only. Signed device receipts and counters establish execution outcomes.')
    try:
        for level in ('baseline', 'hardened', 'intermediate'):
            capture = analyze(directory / f'{level}.pcap',
                              [r for r in report['rows'] if r['level'] == level], level != 'baseline')
            metadata = json.loads((directory / f'{level}.json').read_text())
            capture['capture_process'] = metadata
            capture['expectation_met'] = capture['expectation_met'] and metadata['clean_stop']
            evidence['captures'].append(capture)
        evidence['status'] = 'complete' if all(c['expectation_met'] for c in evidence['captures']) else 'inconclusive'
    except Exception as exc:
        evidence['error'] = f'{type(exc).__name__}: {exc}'
    report['packet_analysis'] = evidence
    report['all_expectations_met'] = bool(report.get('device_expectations_met') and report.get('controls_restored') and evidence['status'] == 'complete')
    temp = report_path.with_suffix('.tmp')
    temp.write_text(json.dumps(report, indent=2))
    temp.replace(report_path)
    (directory / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps(evidence, indent=2))
    if not report['all_expectations_met']:
        raise SystemExit('Demo evidence incomplete or unexpected; inspect guided-demo.json.')


if __name__ == '__main__':
    main()
