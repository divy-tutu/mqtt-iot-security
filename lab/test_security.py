import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from security import CMD, LockPolicy, authenticate, compact, sign

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        key=Ed25519PrivateKey.generate()
        self.private=self.root/"key.pem"
        self.public=self.root/"key.pub"
        self.private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        self.policy=LockPolicy(self.root/"state.db",True,self.public)
    def tearDown(self):
        self.temp.cleanup()
    def command(self,**overrides):
        return sign(self.private,"operator",CMD,{"cmd":"UNLOCK"},**overrides)
    def test_replay_survives_receiver_restart(self):
        payload=self.command()
        self.assertTrue(self.policy.process(payload)["accepted"])
        restarted=LockPolicy(self.root/"state.db",True,self.public)
        self.assertEqual(restarted.process(payload)["reason"],"replay")
        self.assertEqual(restarted.state(),{"state":"UNLOCKED","actions":1})
    def test_sender_restart_needs_no_sequence_reset(self):
        self.assertTrue(self.policy.process(self.command())["accepted"])
        self.assertTrue(self.policy.process(self.command())["accepted"])
    def test_topic_bound_signature(self):
        result=self.policy.process(self.command(topic="another/topic"))
        self.assertEqual(result["reason"],"identity-or-topic")
    def test_expired_and_future(self):
        for ts in (time.time()-60,time.time()+60):
            self.assertEqual(self.policy.process(self.command(ts=ts))["reason"],"stale-timestamp")
    def test_forgery(self):
        outer=json.loads(self.command())
        body=json.loads(outer["msg"])
        body["data"]["cmd"]="LOCK"
        outer["msg"]=compact(body)
        self.assertEqual(self.policy.process(compact(outer))["reason"],"bad-signature")
    def test_retained_command_rejected(self):
        self.assertEqual(self.policy.process(self.command(),retained=True)["reason"],"retained-command")
    def test_schema_and_malformed_dont_crash(self):
        for payload in ('null','[]','{"msg":"null"}','{}',b'\xff'):
            self.assertFalse(self.policy.process(payload)["accepted"])
        for data in ({},{"cmd":[]},{"cmd":"OPEN"},{"cmd":"LOCK","extra":1}):
            self.assertEqual(self.policy.process(self.command(data=data))["reason"],"command-schema")
    def test_bad_metadata(self):
        for field,value in (("sender",[]),("id",{}),("ts",True),("v",True)):
            self.assertFalse(self.policy.process(self.command(**{field:value}))["accepted"])
    def test_rate_limit_and_recovery(self):
        now=time.time()
        for _ in range(5):
            self.assertTrue(self.policy.process(self.command(),now=now)["accepted"])
        self.assertEqual(self.policy.process(self.command(),now=now)["reason"],"command-rate")
        self.assertTrue(self.policy.process(self.command(),now=now+3)["accepted"])
    def test_baseline_has_schema_but_no_replay_check(self):
        policy=LockPolicy(self.root/"baseline.db",False,self.public)
        payload=self.command()
        self.assertTrue(policy.process(payload)["accepted"])
        self.assertTrue(policy.process(payload)["accepted"])
        self.assertFalse(policy.process(self.command(data={"cmd":"DROP"}))["accepted"])
    def test_rejected_message_does_not_poison_replay_state(self):
        good=self.command()
        bad=json.loads(good)
        bad["sig"]=base64.b64encode(b"x"*64).decode()
        self.assertFalse(self.policy.process(compact(bad))["accepted"])
        self.assertTrue(self.policy.process(good)["accepted"])
    def test_decision_chain_links_and_state_is_consistent(self):
        first=self.policy.process(self.command())
        second=self.policy.process(self.command())
        self.assertEqual(second["previous"],first["hash"])
        self.assertEqual(second["actions"],self.policy.state()["actions"])
    def test_packet_cap(self):
        self.assertEqual(self.policy.process("x"*4097)["reason"],"payload-too-large")

if __name__=="__main__":
    unittest.main()

