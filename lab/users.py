"""Persistent browser accounts; passwords are hashed before any database write."""
from contextlib import contextmanager
import re
import sqlite3
import time
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

METHODS = {'hardened': 'scrypt:32768:8:3', 'baseline': 'pbkdf2:sha256:600000'}

class UserStore:
    def __init__(self, path, profile, bootstrap=None):
        self.path, self.profile = str(path), profile
        self.method = METHODS[profile]
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN (\'admin\',\'operator\')), legacy_hint TEXT, created REAL NOT NULL)')
            if bootstrap:
                db.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?, NULL, ?)',
                           (bootstrap['user'], bootstrap['password_hash'], 'admin', time.time()))
        self.dummy_hash = generate_password_hash('not-a-real-account', method=self.method, salt_length=16)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def normalize(username):
        if not isinstance(username, str) or not re.fullmatch(r'[a-zA-Z0-9_.-]{3,32}', username):
            raise ValueError('Username must be 3–32 letters, digits, dots, underscores or hyphens.')
        return username.lower()

    def create(self, username, password, role='operator'):
        username = self.normalize(username)
        if not isinstance(password, str) or not 8 <= len(password) <= 128:
            raise ValueError('Password must contain 8–128 characters.')
        if role not in ('admin', 'operator'):
            raise ValueError('Invalid role.')
        password_hash = generate_password_hash(password, method=self.method, salt_length=16)
        hint = password[-2:] if self.profile == 'baseline' else None
        with self.connect() as db:
            try:
                db.execute('INSERT INTO users VALUES (?, ?, ?, ?, ?)', (username, password_hash, role, hint, time.time()))
            except sqlite3.IntegrityError:
                raise ValueError('Username already exists.') from None
        return username

    def get(self, username):
        with self.connect() as db:
            row = db.execute('SELECT username, role FROM users WHERE username=?', (username,)).fetchone()
        return dict(row) if row else None

    def verify(self, username, password):
        if not isinstance(password, str) or len(password) > 128:
            return None
        try:
            username = self.normalize(username)
        except ValueError:
            username = ''
        with self.connect() as db:
            row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        valid = check_password_hash(row['password_hash'] if row else self.dummy_hash, password)
        if not row or not valid:
            return None
        # Existing single-admin hashes are migrated on successful password login.
        if row['password_hash'].split('$')[0] != self.method:
            password_hash = generate_password_hash(password, method=self.method, salt_length=16)
            with self.connect() as db:
                db.execute('UPDATE users SET password_hash=?, legacy_hint=? WHERE username=?',
                           (password_hash, password[-2:] if self.profile == 'baseline' else None, username))
        return self.get(username)

    def list_for_admin(self):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM users ORDER BY created, username').fetchall()
        return [dict(username=r['username'], role=r['role'], created=r['created'],
                     password_hash=r['password_hash'], method=r['password_hash'].split('$')[0],
                     salt_characters=len(r['password_hash'].split('$')[1]),
                     legacy_hint=('••••••••' + r['legacy_hint']) if self.profile == 'baseline' and r['legacy_hint'] else None)
                for r in rows]

if __name__ == '__main__':
    import json
    import os
    import sys
    # Provision through stdin, never passwords in command arguments or source files.
    data = json.load(sys.stdin)
    store = UserStore('/data/users.sqlite', os.environ['PROFILE'])
    store.create(data['username'], data['password'], data.get('role', 'operator'))
    print('Account created; password not printed.')
