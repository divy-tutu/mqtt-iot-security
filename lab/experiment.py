"""Bounded attacks against ONLY the two named Docker lab brokers.

The runner has fixture access to an operator key to create known-good samples.
A replay attacker needs a captured application envelope and publish permission;
this is not replay of TLS ciphertext.
"""
import argparse
import hashlib
import json
import math
import statistics
import threading
import time
from pathlib import Path
from security import CMD, STATE, EVENT, TOPICS, authenticate, compact, decode, sign
from transport import client, start

ROOT=Path("/runtime")
RESULTS=Path("/results")

class Peer:
    def __init__(self,profile,who="operator",anonymous=False,bad_password=False):
        self.condition=threading.Condition()
        self.messages=[]
        self.acks={}
        self.subacks={}
        self.c=client(who,profile,root=str(ROOT/who),public=str(ROOT/"public"),anonymous=anonymous,bad_password=bad_password)
        def message(c,u,m):
            with self.condition:
                self.messages.append((m.topic,m.payload,time.monotonic()))
                self.condition.notify_all()
        def ack(c,u,mid,reason,props):
            with self.condition:
                self.acks[mid]=reason.value
                self.condition.notify_all()
        def suback(c,u,mid,reasons,props):
            with self.condition:
                self.subacks[mid]=[r.value for r in reasons]
                self.condition.notify_all()
        self.c.on_message,self.c.on_publish,self.c.on_subscribe=message,ack,suback
        start(self.c)
    def subscribe(self,topic):
        _,mid=self.c.subscribe(topic,qos=1)
        with self.condition:
            if not self.condition.wait_for(lambda:mid in self.subacks,5):
                raise TimeoutError("SUBACK missing")
            return self.subacks[mid]
    def send(self,topic,payload,retain=False):
        before=time.monotonic()
        info=self.c.publish(topic,payload,qos=1,retain=retain)
        with self.condition:
            if not self.condition.wait_for(lambda:info.mid in self.acks,5):
                raise TimeoutError("PUBACK missing")
            return self.acks.pop(info.mid),before
    def decision(self,payload,after,timeout=3):
        digest=hashlib.sha256(payload.encode()).hexdigest()
        def find():
            for topic,wire,received in self.messages:
                if topic==EVENT and received>=after:
                    try:
                        body=authenticate(wire,EVENT,"lock",ROOT/"public/lock.pem")
                        if body["data"].get("payload_sha256")==digest:
                            return {**body["data"],"latency_ms":(received-after)*1000}
                    except ValueError:
                        pass
        with self.condition:
            self.condition.wait_for(lambda:find() is not None,timeout)
            return find()
    def close(self):
        self.c.disconnect()
        self.c.loop_stop()

def envelope(cmd="UNLOCK",**kwargs):
    return sign(ROOT/"operator/signing.pem","operator",CMD,{"cmd":cmd},**kwargs)

def run_profile(profile,repeat):
    rows=[]
    def add(name,ok,**evidence):
        rows.append({"profile":profile,"repeat":repeat,"scenario":name,"expectation_met":bool(ok),**evidence})
        print(compact(rows[-1]),flush=True)
    for name,options in (("anonymous",{"anonymous":True}),("wrong-password",{"bad_password":True})):
        try:
            peer=Peer(profile,**options)
            peer.close()
            add(name,False,outcome="unexpected-connect")
        except PermissionError as exc:
            add(name,True,outcome="authentication-rejected",reason=str(exc))
    observer=Peer(profile)
    operator=Peer(profile)
    camera=Peer(profile,"camera")
    try:
        observer.subscribe(EVENT)
        observer.subscribe(STATE)
        def trial(name,payload,peer=operator,expected="accepted",retain=False):
            code,when=peer.send(CMD,payload,retain)
            decision=observer.decision(payload,when)
            if code>=128:
                outcome="broker-rejected"
            elif decision:
                outcome=decision["reason"]
            else:
                outcome="inconclusive"
            add(name,outcome==expected,outcome=outcome,puback=code,decision=decision)
            return decision
        time.sleep(2.1)
        trial("legitimate-command",envelope("LOCK"))
        trial("camera-to-lock",sign(ROOT/"camera/signing.pem","camera",CMD,{"cmd":"UNLOCK"}),camera,"broker-rejected" if profile=="hardened" else "accepted")
        # Schema-valid forged telemetry; PUBACK explicitly carries authorization result.
        forged=sign(ROOT/"camera/signing.pem","camera",STATE,{"state":"UNLOCKED","actions":999})
        code,when=camera.send(STATE,forged)
        with observer.condition:
            observer.condition.wait_for(lambda:any(t==STATE and p.decode()==forged and ts>=when for t,p,ts in observer.messages),1)
            delivered=any(t==STATE and p.decode()==forged and ts>=when for t,p,ts in observer.messages)
        add("camera-state-forgery",(code>=128 and not delivered) if profile=="hardened" else delivered,
            outcome="broker-rejected" if code>=128 else "forged-state-delivered" if delivered else "inconclusive",puback=code)
        camera.subscribe("home/#")
        time.sleep(2.3)
        disclosed=sorted({t for t,_,_ in camera.messages})
        add("wildcard-disclosure",not disclosed if profile=="hardened" else STATE in disclosed,
            outcome="no-topics-disclosed" if not disclosed else "topics-disclosed",topics=disclosed,
            observation_seconds=2.3)
        captured=envelope()
        trial("replay-original",captured)
        trial("replay-copy",captured,expected="replay" if profile=="hardened" else "accepted")
        time.sleep(2.1)
        tampered=json.loads(envelope("LOCK"))
        body=json.loads(tampered["msg"])
        body["data"]["cmd"]="UNLOCK"
        tampered["msg"]=compact(body)
        trial("modified-payload",compact(tampered),expected="bad-signature" if profile=="hardened" else "accepted")
        trial("stale-command",envelope(ts=time.time()-60),expected="stale-timestamp" if profile=="hardened" else "accepted")
        trial("invalid-command-schema",envelope(data={"cmd":"OPEN"}),expected="command-schema")
        trial("malformed-envelope","[]",expected="malformed-envelope")
        trial("retained-command",envelope(),expected="retained-command" if profile=="hardened" else "accepted",retain=True)
        # Remove our retained fixture; empty payload rejection is expected but not scored.
        operator.send(CMD,"",retain=True)
        time.sleep(2.1)
        batch=[]
        for i in range(12):
            payload=envelope("LOCK" if i%2 else "UNLOCK")
            code,when=operator.send(CMD,payload)
            batch.append((payload,when,code))
            time.sleep(0.05)
        decisions=[observer.decision(payload,when) for payload,when,_ in batch]
        accepted=sum(bool(d and d["accepted"]) for d in decisions)
        limited=sum(bool(d and d["reason"]=="command-rate") for d in decisions)
        complete=all(d is not None for d in decisions)
        add("bounded-command-burst",complete and (0<accepted<=5 and limited>=7 if profile=="hardened" else accepted==12),
            outcome="rate-limited" if limited else "all-accepted" if accepted==12 else "inconclusive",
            sent=12,requested_interval_ms=50,accepted=accepted,rate_rejected=limited,
            decisions=decisions)
        time.sleep(2.1)
        trial("post-burst-recovery",envelope("LOCK"))
        latencies=[r["decision"]["latency_ms"] for r in rows if r.get("decision") and r["decision"]["accepted"]]
        add("latency-observation",bool(latencies),outcome="measured",samples=len(latencies),
            median_ms=statistics.median(latencies) if latencies else None,
            p95_ms=sorted(latencies)[math.ceil(.95*len(latencies))-1] if latencies else None)
    finally:
        camera.close()
        operator.close()
        observer.close()
    return rows

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--repeats",type=int,default=3,choices=range(1,6))
    args=parser.parse_args()
    rows=[]
    error=None
    try:
        for repeat in range(1,args.repeats+1):
            # Alternate order to reduce systematic warm-up/order bias.
            for profile in (("baseline","hardened") if repeat%2 else ("hardened","baseline")):
                rows.extend(run_profile(profile,repeat))
    except Exception as exc:
        error=f"{type(exc).__name__}: {exc}"
    RESULTS.mkdir(exist_ok=True)
    report={"schema":1,"created_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "repeats":args.repeats,"parameters":{"freshness_s":30,"command_limit":5,"command_window_s":2,
            "burst_count":12,"burst_interval_ms":50,"qos":1,"telemetry_interval_s":2},
            "error":error,"rows":rows,"all_expectations_met":not error and bool(rows) and all(r["expectation_met"] for r in rows)}
    (RESULTS/"latest.json").write_text(json.dumps(report,indent=2))
    lines=["# Measured experiment results","","These results come from live local MQTT traffic and signed device decisions.","",
           "| Profile | Scenario | Repetition | Observed outcome | Expected behavior matched |",
           "|---|---|---:|---|---|"]
    lines += [f"| {r['profile']} | {r['scenario']} | {r['repeat']} | {r['outcome']} | {r['expectation_met']} |" for r in rows]
    if error:
        lines+=["",f"Experiment error: {error}"]
    (RESULTS/"latest.md").write_text("\n".join(lines))
    print(f"Report: /results/latest.json; all expectations met: {report['all_expectations_met']}")
    raise SystemExit(0 if report["all_expectations_met"] else 1)

if __name__=="__main__":
    main()


