"""Check a stored decision chain; save the reported head independently."""
import hashlib
import json
import sqlite3
import sys
from security import compact

db=sqlite3.connect("file:/data/lock.sqlite?mode=ro",uri=True)
previous="0"*64
count=0
for n,body,digest in db.execute("SELECT n,body,hash FROM decisions ORDER BY n"):
    event=json.loads(body)
    if n!=count+1 or event["n"]!=n or event["previous"]!=previous or hashlib.sha256(body.encode()).hexdigest()!=digest:
        sys.exit(f"Broken decision chain at record {n}")
    previous=digest
    count+=1
print(compact({"records":count,"head":previous,"chain_valid":True,
               "limitation":"Without an independent saved head, complete history rewrite or tail deletion cannot be excluded."}))

