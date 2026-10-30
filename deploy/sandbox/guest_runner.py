"""Fixed VM bootstrap. Generated programs inherit only the bounded stdio RPC channel."""
import json
import os
import resource
import sys
import tempfile

# Do not buffer bytes from the next protocol message before handing stdin to the program.
raw=bytearray()
while not raw.endswith(b'\n') and len(raw)<1_100_000:
    chunk=os.read(0,1)
    if not chunk:break
    raw.extend(chunk)
payload=json.loads(raw)
resource.setrlimit(resource.RLIMIT_CPU,(8,8))
resource.setrlimit(resource.RLIMIT_FSIZE,(1_048_576,1_048_576))
resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
scratch=tempfile.mkdtemp(prefix='analysis-')
source=os.path.join(scratch,'analysis.py' if payload['language']=='python' else 'analysis.sh')
with open(source,'w') as f:f.write(payload['source'])
argv=['/usr/bin/python3','-I',source] if payload['language']=='python' else ['/bin/bash','--noprofile','--norc',source]
os.chdir(scratch)
os.execve(argv[0],argv,{'PATH':'/usr/bin:/bin','HOME':scratch,'TMPDIR':scratch,'LANG':'C.UTF-8'})
