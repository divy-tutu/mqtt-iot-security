"""Local fixture tool. Prints the signed device decision, never private keys."""
import argparse
import json
from pathlib import Path
from experiment import Peer, envelope
from security import CMD, EVENT

parser=argparse.ArgumentParser()
parser.add_argument("cmd",choices=["LOCK","UNLOCK"])
parser.add_argument("--profile",choices=["baseline","hardened"],default="hardened")
parser.add_argument("--save",action="store_true")
parser.add_argument("--replay",action="store_true")
parser.add_argument("--expect",choices=["accepted","replay"])
args=parser.parse_args()
fixture=Path("/results/restart-command.json")
payload=fixture.read_text() if args.replay else envelope(args.cmd)
if args.save:
    fixture.write_text(payload)
observer=Peer(args.profile)
sender=Peer(args.profile)
try:
    observer.subscribe(EVENT)
    code,when=sender.send(CMD,payload)
    decision=observer.decision(payload,when)
    print(json.dumps({"puback":code,"decision":decision},indent=2))
    Path("/results/last-operator-decision.json").write_text(json.dumps(decision,indent=2))
    raise SystemExit(0 if decision and decision["reason"]==(args.expect or ("replay" if args.replay else "accepted")) else 1)
finally:
    sender.close()
    observer.close()


