"""Send the reviewed read-only verifier through strictly pinned SSH; print no secrets."""
import json
import os
from pathlib import Path
import subprocess
# Live target is supplied by the operator; nothing about it is stored in the repository.
HOST = os.environ['VELUM_LIVE_HOST']
PORT = os.environ['VELUM_LIVE_PORT']
import sys
root = Path(__file__).resolve().parents[1]
payload = (root / 'tools/live-backup-independent-readback.py').read_bytes()
if '--trial' in sys.argv:
    payload = b'REQUIRE_TRIAL = True\n' + payload
result = subprocess.run(['ssh', '-T', '-i', os.environ['VELUM_LIVE_SSH_KEY'],
    '-p', PORT, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
    'root@' + HOST, 'python3', '-I', '-'],
    input=payload, capture_output=True, timeout=90)
if result.returncode:
    # Avoid exposing incidental private paths from remote tracebacks.
    raise SystemExit('Independent verification failed; inspect the bounded read-only verifier before proceeding')
proof = json.loads(result.stdout)
assert proof['verified'] is True
out = root / 'build/live-backup-ui/independent-proof.json'
out.write_text(json.dumps(proof, indent=2), encoding='utf-8')
print(json.dumps(proof))
