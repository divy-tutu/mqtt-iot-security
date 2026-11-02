"""Local gateway account integration checks; credentials are read only from stdin."""
import http.cookiejar
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from users import UserStore

def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def request(opener, path, data=None):
    req = urllib.request.Request('http://localhost:8000'+path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type':'application/json'})
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)

def main():
    credentials = json.load(sys.stdin)
    profile = os.environ['PROFILE']
    store = UserStore('/data/users.sqlite', profile)
    temporary_user = 'test_'+secrets.token_hex(6)
    secret = secrets.token_urlsafe(24)
    admin, operator = client(), client()
    checks = {}
    try:
        checks['anonymous-list-rejected'] = request(admin, '/admin/users')[0] == 401
        checks['owner-login'] = request(admin, '/login', credentials)[0] == 200
        code, body = request(admin, '/snapshot')
        checks['correct-owner-role'] = code == 200 and body['user'] == {'username':credentials['username'], 'role':'admin'}
        checks['admin-create-operator'] = request(admin, '/admin/users', {'username':temporary_user, 'password':secret})[0] == 201
        code, body = request(admin, '/admin/users')
        owner = next(r for r in body.get('users', []) if r['username'] == credentials['username'])
        checks['correct-hash-method'] = owner['method'] == store.method
        checks['correct-hint-policy'] = owner['legacy_hint'] == ('••••••••'+credentials['password'][-2:] if profile == 'baseline' else None)
        checks['no-plaintext-in-list'] = credentials['password'] not in json.dumps(body)
        checks['operator-login'] = request(operator, '/login', {'username':temporary_user, 'password':secret})[0] == 200
        checks['operator-list-forbidden'] = request(operator, '/admin/users')[0] == 403
        checks['operator-create-admin-forbidden'] = request(operator, '/admin/users', {'username':'forbidden', 'password':secret, 'role':'admin'})[0] == 403
        checks['operator-access-log-forbidden'] = request(operator, '/access-log')[0] == 403
        checks['operator-snapshot-has-no-hashes'] = 'password_hash' not in json.dumps(request(operator, '/snapshot')[1])
        with admin.open('http://localhost:8000/snapshot', timeout=10) as response:
            checks['polling-does-not-reissue-session-cookie'] = 'Set-Cookie' not in response.headers
        checks['logout-revokes-list-access'] = request(admin, '/logout', {})[0] == 200 and request(admin, '/admin/users')[0] == 401
        checks['no-plaintext-in-user-database'] = credentials['password'].encode() not in open('/data/users.sqlite', 'rb').read()
    finally:
        with store.connect() as db:
            db.execute('DELETE FROM users WHERE username=?', (temporary_user,))
    print(json.dumps({'profile':profile, 'checks':checks}, indent=2))
    if not all(checks.values()):
        raise SystemExit('Account checks failed')

if __name__ == '__main__':
    main()
