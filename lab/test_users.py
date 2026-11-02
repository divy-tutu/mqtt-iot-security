import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from users import UserStore
import webauthn_auth as passkeys
from webauthn.helpers import bytes_to_base64url

class AccountTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = UserStore(self.root/'users.db', 'hardened')
    def tearDown(self):
        self.temp.cleanup()
    def test_unique_salts_and_no_plaintext_or_hints(self):
        secret = 'Example-test-password!'
        self.store.create('alice', secret)
        self.store.create('bob', secret)
        rows = self.store.list_for_admin()
        self.assertNotEqual(rows[0]['password_hash'], rows[1]['password_hash'])
        self.assertEqual(len(rows[0]['password_hash']), len(rows[1]['password_hash']))
        self.assertTrue(all(r['legacy_hint'] is None for r in rows))
        self.assertNotIn(secret.encode(), (self.root/'users.db').read_bytes())
        self.assertEqual(self.store.verify('ALICE', secret)['role'], 'operator')
        self.assertIsNone(self.store.verify('alice', 'wrong'))
        self.assertIsNone(self.store.verify('absent', secret))
    def test_baseline_hint_fixed_mask_only(self):
        baseline = UserStore(self.root/'baseline.db', 'baseline')
        baseline.create('alice', 'Example-test-password!')
        row = baseline.list_for_admin()[0]
        self.assertEqual(row['legacy_hint'], '••••••••d!')
        self.assertTrue(row['password_hash'].startswith('pbkdf2:sha256:600000$'))
    def test_duplicates_validation_and_role(self):
        self.store.create('Alice', 'test-password', 'admin')
        with self.assertRaises(ValueError): self.store.create('alice', 'another-password')
        with self.assertRaises(ValueError): self.store.create("x' OR 1=1", 'test-password')
        with self.assertRaises(ValueError): self.store.create('bob', 'short')
        with self.assertRaises(ValueError): self.store.create('bob', 'test-password', 'root')
        self.assertEqual(self.store.get('alice')['role'], 'admin')

class PasskeyOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name)/'passkeys.db')
        self.patch = patch.object(passkeys, 'DB_PATH', self.path)
        self.patch.start()
    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()
    def test_existing_single_admin_credentials_migrate(self):
        db = sqlite3.connect(self.path)
        db.execute('CREATE TABLE credentials (credential_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, sign_count INTEGER NOT NULL)')
        db.execute("INSERT INTO credentials VALUES ('old','public',0)")
        db.commit(); db.close()
        db = passkeys._connect()
        self.assertEqual(db.execute('SELECT username FROM credentials').fetchone()[0], 'admin')
        db.close()
    def test_passkey_returns_its_owner_not_admin(self):
        verification = SimpleNamespace(credential_id=b'credential', credential_public_key=b'key', sign_count=0)
        with patch.object(passkeys, 'verify_registration_response', return_value=verification):
            passkeys.verify_registration({}, bytes_to_base64url(b'challenge'), 'alice')
        request = {'id': bytes_to_base64url(b'credential'), 'response': {'userHandle': bytes_to_base64url(b'alice')}}
        with patch.object(passkeys, 'verify_authentication_response', return_value=SimpleNamespace(new_sign_count=1)):
            self.assertEqual(passkeys.verify_authentication(request, bytes_to_base64url(b'challenge')), 'alice')
            request['response']['userHandle'] = bytes_to_base64url(b'admin')
            self.assertIsNone(passkeys.verify_authentication(request, bytes_to_base64url(b'challenge')))
    def test_challenges_expire_and_cannot_be_replayed_or_rebound(self):
        passkeys.save_challenge('one', 'register', 'alice')
        self.assertFalse(passkeys.consume_challenge('one', 'register', 'admin'))
        self.assertTrue(passkeys.consume_challenge('one', 'register', 'alice'))
        self.assertFalse(passkeys.consume_challenge('one', 'register', 'alice'))
        passkeys.save_challenge('expired', 'login')
        with patch.object(passkeys.time, 'time', return_value=10**12):
            self.assertFalse(passkeys.consume_challenge('expired', 'login'))

if __name__ == '__main__':
    unittest.main()
