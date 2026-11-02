"""Unit checks for evidence classification; not a substitute for live PCAP tests."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

# These checks can run without host TShark/PyShark; live parsing runs in Docker.
spec = importlib.util.spec_from_file_location('packet_analysis', Path(__file__).with_name('analyze.py'))
module = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'pyshark': NS()}):
    spec.loader.exec_module(module)


class Capture(list):
    def close(self):
        self.closed = True


class EvidenceTests(unittest.TestCase):
    def run_capture(self, packets, encrypted=False, digest=None):
        rows = [dict(started_epoch=10, finished_epoch=20, payload_sha256=digest)]
        capture = Capture(packets)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'test.pcap'
            path.write_bytes(b'test-fixture')
            with patch.object(module.pyshark, 'FileCapture', return_value=capture, create=True):
                result = module.analyze(path, rows, encrypted, root=root)
        self.assertTrue(capture.closed)
        return result, rows[0]['packet_evidence']

    def test_empty_capture_cannot_confirm_encryption(self):
        result, _ = self.run_capture([], encrypted=True)
        self.assertFalse(result['expectation_met'])

    def test_handshake_only_cannot_confirm_application_traffic(self):
        result, _ = self.run_capture([NS(sniff_timestamp='15', number='1', layers=[NS(layer_name='tls')])], True)
        self.assertFalse(result['expectation_met'])

    def test_encrypted_capture_does_not_claim_payload_match(self):
        result, evidence = self.run_capture([NS(sniff_timestamp='15', number='1', layers=[NS(layer_name='tls', app_data='opaque')])], True, 'hash')
        self.assertTrue(result['expectation_met'])
        self.assertEqual(evidence['matching_payload_frames'], [])
        self.assertIn('time-window-only', evidence['correlation'])

    def test_visible_payload_requires_matching_time_window(self):
        payload = b'captured command'
        digest = hashlib.sha256(payload).hexdigest()
        layer = NS(layer_name='mqtt', msg=NS(all_fields=[NS(show=payload.hex())]))
        result, evidence = self.run_capture([NS(sniff_timestamp='15', number='7', layers=[layer])], digest=digest)
        self.assertTrue(result['expectation_met'])
        self.assertEqual(evidence['matching_payload_frames'], [7])
        result, _ = self.run_capture([NS(sniff_timestamp='25', number='7', layers=[layer])], digest=digest)
        self.assertFalse(result['expectation_met'])

    def test_unrelated_plaintext_is_not_attack_evidence(self):
        layer = NS(layer_name='mqtt', msg=NS(all_fields=[NS(show=b'other'.hex())]))
        result, _ = self.run_capture([NS(sniff_timestamp='15', number='1', layers=[layer])], digest='unmatched')
        self.assertFalse(result['expectation_met'])


if __name__ == '__main__':
    unittest.main()
