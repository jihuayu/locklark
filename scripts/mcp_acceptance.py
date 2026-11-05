"""MCP stdio smoke against a new synthetic release CLI. No live GitHub or vault service."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import tempfile

exe = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix="locklark-mcp-"))
demo = root / "demo"
device = demo / "clients" / "B"
key = root / "runner.sessionkey"

def cli(*args):
    cmd = [exe, *(str(x) for x in args)]
    proc = subprocess.run(cmd, capture_output=True, timeout=30)
    if proc.returncode:
        raise RuntimeError(f"{args[0]} failed: " + proc.stderr.decode(errors="replace"))
    return json.loads(proc.stdout)

cli("demo","--out",demo,"--session","boot","--reason","synthetic")
public=cli("session-keygen","--out",key)["public"]
cli("pull-enroll","--device",device,"--session","job","--public",public,"--repo","example/tools","--repo-id","123","--reason","pull reader")
profile=root/"bridge.profile"
cli("bridge-profile","--device",device,"--session","job","--out",profile)
for dirname in ("private","exchange"):
    (root/dirname).mkdir()
args=[exe,"mcp-stdio","--profile",str(profile),"--session-key",str(key),"--recipient",str(demo/"agent/approval.pub"),"--host-sign-key",str(demo/"agent/host-sign.pub"),"--private",str(root/"private"),"--exchange",str(root/"exchange"),"--inbox",str(demo/"inbox"),"--bun",shutil.which("bun")]
class Bridge:
    def __enter__(self):
        self.proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self.guard=threading.Timer(30,self.proc.kill)
        self.guard.start()
        self.n=0
        self.rpc("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"acceptance","version":"1"}})
        self.send({"jsonrpc":"2.0","method":"notifications/initialized"})
        return self
    def send(self, msg):
        self.proc.stdin.write(json.dumps(msg).encode()+b"\n"); self.proc.stdin.flush()
    def rpc(self, method, params):
        self.n+=1; self.send({"jsonrpc":"2.0","id":self.n,"method":method,"params":params})
        while True:
            raw=self.proc.stdout.readline()
            if not raw: raise RuntimeError("bridge exited before reply")
            msg=json.loads(raw)
            if msg.get("id")==self.n:
                if "error" in msg: raise RuntimeError(msg["error"])
                return msg["result"]
    def tool(self,name,args):
        res=self.rpc("tools/call",{"name":name,"arguments":args})
        assert not res.get("isError"),res
        return json.loads(res["content"][0]["text"])
    def __exit__(self,*_):
        self.proc.stdin.close()
        try: self.proc.wait(timeout=5)
        finally:
            self.guard.cancel()
            if self.proc.poll() is None: self.proc.kill(); self.proc.wait()

call={"repo":"123","number":7,"reason":"check merge","request_key":"0123456789abcdef0123456789abcdef"}
with Bridge() as b:
    assert {t["name"] for t in b.rpc("tools/list",{})["tools"]}=={"github_pulls_get","locklark_resume","locklark_collect"}
    first=b.tool("github_pulls_get",call)
with Bridge() as b:
    retried=b.tool("github_pulls_get",call)
    assert first==retried and len(list((demo/"inbox").glob("*.request.age")))==1
    conflict=b.rpc("tools/call",{"name":"github_pulls_get","arguments":{**call,"number":8}})
    assert conflict["isError"]
    request={"request_id":first["id"],"review":first["review"]}
    waiting=b.tool("locklark_resume",request)
    assert waiting["state"]=="awaiting-holder"
cli("status-serve","--once","--device",device,"--inbox",demo/"inbox","--exchange",root/"exchange","--session","job","--profile",profile)
with Bridge() as b:
    observed=b.tool("locklark_resume",{**request,"poll_id":waiting["poll_id"]})
    assert observed["state"]=="pending" and observed["request_id"]==first["id"] and observed["observed_at"]
    assert b.tool("locklark_collect",request)["state"]=="awaiting-receipt"
assert not cli("executions","--device",device,"--session","job")
cli("decide","--device",device,"--inbox",demo/"inbox","--bundle",demo/"share/epoch-3","--id",first["id"],"--review",first["review"],"--choice","approve","--reason","only this recorded pull")
recording=root/"recorded.json"
recording.write_text(json.dumps({"number":7,"state":"open","merged_at":None,"base":{"repo":{"id":123}},"body":"never deliver"}))
ticket=root/"exchange"/(first["id"]+".invoke.age")
original_ticket=ticket.read_bytes()
with Bridge() as b:
    assert b.tool("locklark_collect",request)["state"]=="awaiting-receipt"
assert not cli("executions","--device",device,"--session","job")
cli("invoke-run","--device",device,"--bundle",demo/"share/epoch-3","--ticket",ticket,"--recorded-response",recording,"--out",root/"holder-reply.age")
cli("status-serve","--once","--device",device,"--inbox",demo/"inbox","--exchange",root/"exchange")
assert (root/"exchange"/(first["id"]+".result.age")).read_bytes()==(root/"holder-reply.age").read_bytes()
for _ in range(2):
    with Bridge() as b:
        got=b.tool("locklark_collect",request)
        assert got=={"state":"succeeded","request_id":first["id"],"result":{"source":"recorded-response/v1","pull":{"number":7,"state":"open","merged_at":None}}}
        assert b.tool("github_pulls_get",call)==first
assert ticket.read_bytes()==original_ticket
log=cli("executions","--device",device,"--session","job")
assert len(log)==1 and log[0]["state"]=="succeeded"
if len(sys.argv)>2:
    # Same signed enrollment, directory and delivered receipt, but a binary
    # shipping different plugin bytes: allow historical reads, not new calls.
    args[0]=str(Path(sys.argv[2]).resolve())
    with Bridge() as b:
        assert {t["name"] for t in b.rpc("tools/list",{})["tools"]}=={"locklark_collect","locklark_resume"}
        assert b.tool("locklark_collect",request)==got
    print("PASS: upgraded bridge still reads old receipts without exposing the retired action")
print("PASS: MCP reconnect, idempotent submission, read-only status and signed result collection without re-execution")
