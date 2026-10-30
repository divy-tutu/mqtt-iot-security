"""Server-held MQTT credentials and signing key; browser gets session + verified data."""
import collections
import json
import os
import threading
import time
from pathlib import Path
from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash
from security import CMD, EVENT, TOPICS, authenticate, decode, sign
from transport import client, start, publish
import access_log
import webauthn_auth
from webauthn import options_to_json

app = Flask(__name__)
auth = json.loads(Path("/auth/auth.json").read_text())
app.config.update(SECRET_KEY=auth["session_key"], SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_NAME="mqtt_"+os.environ["PROFILE"],
                  SESSION_COOKIE_PATH="/", MAX_CONTENT_LENGTH=4096,
                  PERMANENT_SESSION_LIFETIME=1800)
profile = os.environ["PROFILE"]
guard = threading.Lock()
messages, events = {}, collections.deque(maxlen=100)
login_attempts = collections.deque(maxlen=100)
command_times = collections.deque(maxlen=100)
connected = False
c = client("gateway")
topic_sender = {topic:who for who,topic in TOPICS.items()}
topic_sender[EVENT] = "lock"

def on_connect(c, userdata, flags, reason, properties):
    global connected
    connected = not reason.is_failure
    if connected:
        for topic in topic_sender:
            c.subscribe(topic, qos=1)

def on_disconnect(c, userdata, flags, reason, properties):
    global connected
    connected = False

def on_message(c, userdata, msg):
    if msg.topic not in topic_sender:
        return
    try:
        who = topic_sender[msg.topic]
        # Signed decisions are checked even in baseline: independent test instrumentation.
        verified = profile=="hardened" or msg.topic==EVENT
        body = authenticate(msg.payload,msg.topic,who,f"/public/{who}.pem") if verified else decode(msg.payload)[1]
        record = {"topic":msg.topic,"data":body["data"],"received":time.time(),
                  "verified":verified,"id":body.get("id")}
        with guard:
            if msg.topic==EVENT:
                events.appendleft(record)
            else:
                messages[msg.topic]=record
    except (ValueError, KeyError) as exc:
        with guard:
            events.appendleft({"topic":msg.topic,"received":time.time(),"verified":False,
                              "data":{"accepted":False,"reason":str(exc)}})

c.on_connect, c.on_disconnect, c.on_message = on_connect, on_disconnect, on_message

@app.before_request
def protect():
    if request.method=="POST":
        # Browser requests must be JSON; cross-origin form submission is rejected.
        if not request.is_json or request.headers.get("Sec-Fetch-Site")=="cross-site":
            return jsonify(error="same-origin JSON required"),403
    # webauthn/status and the login-ceremony endpoints must be reachable
    # BEFORE a session exists — that's the whole point of a login flow —
    # but register/* stays protected below since only an already-logged-in
    # operator should be able to add a new passkey.
    public_paths = ("/health", "/login", "/webauthn/status", "/webauthn/login/options", "/webauthn/login/verify")
    if request.path not in public_paths and not session.get("user"):
        # No session cookie at all = someone hitting a protected route
        # directly (not just a normal logged-out browser tab), worth a
        # persistent record alongside the login-side logging below.
        access_log.log_event("unauthenticated_request", "unknown", request.path)
        return jsonify(error="authentication required"),401

@app.get("/health")
def health():
    return jsonify(connected=connected,profile=profile),200 if connected else 503

@app.post("/login")
def login():
    now=time.monotonic()
    with guard:
        while login_attempts and login_attempts[0]<now-60:
            login_attempts.popleft()
        if len(login_attempts)>=10:
            access_log.log_event("login_rate_limited", "unknown", "10+ attempts/min")
            return jsonify(error="login rate limit; retry in 60 seconds"),429
        login_attempts.append(now)
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict):
        return jsonify(error="invalid request"),400
    username,password=data.get("username"),data.get("password")
    if not isinstance(password,str) or username!=auth["user"] or not check_password_hash(auth["password_hash"],password):
        # Don't log the submitted password, only the attempted username —
        # same reasoning as not revealing which part (user or password)
        # was wrong in the response above: avoid turning the log itself
        # into a credential-enumeration or credential-leak surface.
        access_log.log_event("login_failed", str(username)[:100] if username else "unknown", "")
        return jsonify(error="invalid credentials"),401
    access_log.log_event("login_success", username, "")
    session.clear()
    session["user"]=username
    session.permanent=True
    return jsonify(ok=True)

@app.post("/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/snapshot")
def snapshot():
    with guard:
        return jsonify(profile=profile,application_policy=os.environ.get("COMMAND_POLICY","full"),connected=connected,messages=messages,events=list(events),server_time=time.time())

@app.post("/command")
def command():
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or set(data)!={"cmd"} or data["cmd"] not in ("LOCK","UNLOCK"):
        return jsonify(error="expected LOCK or UNLOCK"),400
    now=time.monotonic()
    with guard:
        while command_times and command_times[0]<now-2:
            command_times.popleft()
        if len(command_times)>=5:
            access_log.log_event("command_rate_limited", session.get("user","unknown"), "5+ commands/2s")
            return jsonify(error="operator rate limit"),429
        command_times.append(now)
    if not connected:
        return jsonify(error="broker offline"),503
    payload=sign("/identity/signing.pem","operator",CMD,data)
    try:
        publish(c,CMD,payload)
    except (TimeoutError,RuntimeError):
        return jsonify(error="delivery unconfirmed"),503
    # PUBACK is transport evidence only; the signed device event confirms execution.
    return jsonify(status="published-await-device-decision",command_id=decode(payload)[1]["id"]),202

start(c)


@app.get('/report')
def report():
    path=Path('/results/latest.json')
    if not path.exists():
        return jsonify(error='no experiment results yet'),404
    return app.response_class(path.read_text(),mimetype='application/json')


@app.get('/access-log')
def access_log_view():
    # Protected the same way every other route here is: before_request
    # already rejects this above if there's no session cookie.
    return jsonify(events=access_log.recent_events(limit=50))


@app.get("/webauthn/status")
def webauthn_status():
    # Public (see protect() above) so the sign-in page can decide whether
    # to show a "sign in with passkey" option at all.
    return jsonify(registered=webauthn_auth.has_credential())


@app.post("/webauthn/register/options")
def webauthn_register_options():
    # Already requires an authenticated session via protect() above —
    # only an operator who already proved the password can add a passkey.
    options, challenge = webauthn_auth.build_registration_options(session["user"])
    session["webauthn_challenge"] = challenge
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.post("/webauthn/register/verify")
def webauthn_register_verify():
    challenge = session.pop("webauthn_challenge", None)
    if not challenge:
        return jsonify(error="no passkey setup in progress"), 400
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="invalid request"), 400
    try:
        webauthn_auth.verify_registration(data, challenge)
    except Exception as exc:
        access_log.log_event("webauthn_register_failed", session.get("user", "unknown"), str(exc)[:150])
        return jsonify(error="could not verify passkey"), 400
    access_log.log_event("webauthn_register_success", session.get("user", "unknown"), "")
    return jsonify(ok=True)


@app.post("/webauthn/login/options")
def webauthn_login_options():
    options, challenge = webauthn_auth.build_authentication_options()
    session["webauthn_challenge"] = challenge
    return app.response_class(options_to_json(options), mimetype="application/json")


@app.post("/webauthn/login/verify")
def webauthn_login_verify():
    challenge = session.pop("webauthn_challenge", None)
    if not challenge:
        return jsonify(error="no passkey sign-in in progress"), 400
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="invalid request"), 400
    if not webauthn_auth.verify_authentication(data, challenge):
        access_log.log_event("webauthn_login_failed", "unknown", "")
        return jsonify(error="passkey verification failed"), 401
    access_log.log_event("webauthn_login_success", auth["user"], "")
    session.clear()
    session["user"] = auth["user"]
    session.permanent = True
    return jsonify(ok=True)

