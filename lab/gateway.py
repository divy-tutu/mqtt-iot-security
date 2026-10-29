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
    if request.path not in ("/health","/login") and not session.get("user"):
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
            return jsonify(error="login rate limit; retry in 60 seconds"),429
        login_attempts.append(now)
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict):
        return jsonify(error="invalid request"),400
    username,password=data.get("username"),data.get("password")
    if not isinstance(password,str) or username!=auth["user"] or not check_password_hash(auth["password_hash"],password):
        return jsonify(error="invalid credentials"),401
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

