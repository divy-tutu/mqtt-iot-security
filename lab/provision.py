"""Idempotent local lab provisioning; private material stays out of browser builds."""
import datetime as dt
import ipaddress
import json
import os
import secrets
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from werkzeug.security import generate_password_hash

root = Path("/runtime")
root.mkdir(exist_ok=True)
if (root / "provisioned").exists():
    print("Keeping existing lab identities and certificates.")
    raise SystemExit(0)
if any(root.iterdir()):
    raise SystemExit("Incomplete runtime exists. Inspect it before moving it aside and provisioning again.")
for directory in ("public", "tls", "ca-private", "baseline-broker", "hardened-broker", "gateway-auth"):
    (root / directory).mkdir()
for who in ("sensor", "camera", "lock", "operator"):
    folder = root / who
    folder.mkdir()
    key = ed25519.Ed25519PrivateKey.generate()
    (folder / "signing.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "public" / f"{who}.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    (folder / "mqtt.json").write_text(json.dumps({"username": who, "password": secrets.token_urlsafe(24)}))
users = [json.loads((root / who / "mqtt.json").read_text()) for who in ("sensor", "camera", "lock", "operator")]
for profile in ("baseline", "hardened"):
    (root / f"{profile}-broker" / "passwd").write_text("".join(f"{u['username']}:{u['password']}\n" for u in users))
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MQTT Laboratory CA")])
now = dt.datetime.now(dt.timezone.utc)
ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
      .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
      .not_valid_after(now+dt.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True)
      .sign(ca_key,hashes.SHA256()))
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"hardened-broker")]))
          .issuer_name(name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=90))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("hardened-broker"),x509.DNSName("localhost"),
                                                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),False)
          .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),False)
          .sign(ca_key,hashes.SHA256()))
(root/"public"/"ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
(root/"tls"/"server.crt").write_bytes(server.public_bytes(serialization.Encoding.PEM))
for path,key in ((root/"tls"/"server.key",server_key),(root/"ca-private"/"ca.key",ca_key)):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
password = secrets.token_urlsafe(18)
(root/"gateway-auth"/"auth.json").write_text(json.dumps({"user":"admin","password_hash":generate_password_hash(password),"session_key":secrets.token_hex(32)}))
(root/"login.txt").write_text(f"Username: admin\nPassword: {password}\n")
(root/"provisioned").write_text("v2\n")
# Containers run as non-root, receiving only explicitly selected read-only mounts.
# Host file ACLs are still the host owner's responsibility.
for path in root.rglob("*"):
    os.chmod(path, 0o755 if path.is_dir() else 0o444)
print("Provisioned. Operator login is in runtime/login.txt. No private keys are browser assets.")

