# Audit log

Pass a path and every decision is appended to a JSONL file.

```python
shield = Shield.from_policy("policy.yaml", audit="audit.jsonl")
try:
    with shield.session(user="alice", task="triage"):
        ...
finally:
    shield.close()
```

Each record holds a sequence number, timestamp, session, user, task, policy digest, tool,
redacted arguments, verdict, rule and reason. Credential-shaped values are redacted
**before** hashing.

- **Hash chain.** Each record's SHA-256 covers the previous record's hash and all of its own
  fields. Editing, deleting or reordering a record breaks verification.
- **Signed checkpoints** (`[audit]` extra). Every N records an Ed25519 signature covers the
  chain head, so a deleted-and-rehashed chain is detectable without the private key.
- **Resume.** Reopening the file continues the same chain from its tail.
- **Fail-closed.** If a decision cannot be written, the call is denied; an approval that
  cannot be written is not granted.
- **Approvals.** The outcome of every `ask` is a second record with rule `approval`.

```python
from agentshield.audit import AuditLog, load_key

audit = AuditLog("audit.jsonl", key=load_key("key.pem"), checkpoint_every=1000)
shield = Shield.from_policy("policy.yaml", audit=audit)
```

```bash
agentshield audit keygen --out key.pem
agentshield audit verify audit.jsonl          # exit 0 if valid
agentshield audit verify audit.jsonl --json
```

Verification needs only the public key in the file's header. Two limits follow:

- **The unsigned tail.** Records after the last checkpoint are chained but not signed, so
  they can be cut off the end without breaking verification. `shield.close()` signs a final
  checkpoint; after a crash, `audit verify` reports how many records are in the unsigned
  tail. A smaller `checkpoint_every` keeps it short.
- **The header key.** Someone who can rewrite the whole file can replace the key and
  re-sign a forged chain. Anchor the public key outside the file when that matters.

## Flow graph

```bash
python examples/exfil_demo.py --audit demo.jsonl
agentshield ui demo.jsonl --policy policy.yaml   # writes demo.html
```

One self-contained HTML page with one graph per session: the model on the left, each
attempted tool call on the right, coloured by outcome. Blocked calls (denied, or `ask` with
no approval) are red. With `--policy`, dashed edges show `untrusted` and `confidential` data
returning to the model; the log itself does not carry labels. The page runs no script and
every value from the log is HTML-escaped.
