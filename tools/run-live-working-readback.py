"""Run the bounded read-only verifier against the authorized pinned test endpoint."""
import json
import os
from pathlib import Path
import subprocess
# Live target is supplied by the operator; nothing about it is stored in the repository.
HOST = os.environ['VELUM_LIVE_HOST']
PORT = os.environ['VELUM_LIVE_PORT']
import sys
root = Path(__file__).resolve().parents[1]
proof = json.loads((root / 'build/live-backup-ui/independent-proof.json').read_text())
state = sys.argv[1]
assert state in ('inactive', 'active')
prefix = 'EXPECTED_ARCHIVE_SHA = ' + repr(proof['sha256']) + '\nEXPECTED_DATABASE_SHA = ' + repr(proof['databaseSha256']) + '\nEXPECTED_STATE = ' + repr(state) + '\n'
payload = prefix.encode() + (root / 'tools/live-working-restore-readback.py').read_bytes()
result = subprocess.run(['ssh', '-T', '-i', os.environ['VELUM_LIVE_SSH_KEY'],
    '-p', PORT, '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
    'root@' + HOST, 'python3', '-I', '-'], input=payload, capture_output=True, timeout=60)
if result.returncode:
    raise SystemExit('Working restoration readback failed; no mutation or retry was performed')
verified = json.loads(result.stdout)
(root / ('build/live-backup-ui/working-' + state + '-proof.json')).write_text(json.dumps(verified, indent=2), encoding='utf-8')
print(json.dumps(verified))
