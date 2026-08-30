"""Build the deterministic dormant private-release bridge WebJob package."""
import argparse, hashlib, json, stat, tempfile, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; TS=(1980,1,1,0,0,0); JOB="App_Data/jobs/triggered/paperdesk-accepted-release-registry/"
SOURCES=(("scripts/private_release_mailbox.py","private_release_mailbox.py",0o644),("provider/private_release_bridge_runtime.py","private_release_bridge_runtime.py",0o644),("provider/private_release_bridge_azure.py","private_release_bridge_azure.py",0o644),("provider/private_release_bridge_entry.py","private_release_bridge_entry.py",0o644),("contracts/private_release_mailbox_contract.json","private_release_mailbox_contract.json",0o644),("webjobs/paperdesk-private-release-bridge/run.sh","run.sh",0o755),("webjobs/paperdesk-private-release-bridge/settings.job","settings.job",0o644))
class PackageError(RuntimeError): pass
def build(output):
    output=Path(output).resolve()
    if output.exists(): raise PackageError("output-exists")
    bodies=[]
    for source,name,mode in SOURCES:
        path=ROOT/source
        if not path.is_file() or path.is_symlink(): raise PackageError("source")
        body=path.read_bytes().replace(b"\r\n",b"\n")
        if not body or len(body)>2*1024*1024: raise PackageError("source-size")
        bodies.append((name,mode,body))
    contract=json.loads(dict((name,body) for name,_,body in bodies)["private_release_mailbox_contract.json"])
    if any(value is not None for value in contract["activation"].values()): raise PackageError("not-dormant")
    # Provisioning evidence contains the final package digest, so embedding it
    # would create an impossible package-self-hash cycle.  It is supplied as
    # exact canonical transient state under the controller lease instead.
    members={name:hashlib.sha256(body).hexdigest() for name,_,body in bodies}
    manifest=(json.dumps({"schemaVersion":1,"members":members},sort_keys=True,separators=(",",":"))+"\n").encode(); bodies.append(("private_release_bridge_members.json",0o644,manifest))
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent,delete=False) as handle: temp=Path(handle.name)
    try:
        with zipfile.ZipFile(temp,"w",zipfile.ZIP_STORED) as archive:
            for name,mode,body in bodies:
                info=zipfile.ZipInfo(JOB+name,TS); info.create_system=3; info.external_attr=(stat.S_IFREG|mode)<<16; archive.writestr(info,body)
        temp.replace(output)
    finally: temp.unlink(missing_ok=True)
    return {"schemaVersion":1,"status":"dormant","packageSha256":hashlib.sha256(output.read_bytes()).hexdigest(),"members":members}
def main():
    parser=argparse.ArgumentParser();parser.add_argument("--output",required=True);args=parser.parse_args();print(json.dumps(build(args.output),sort_keys=True,separators=(",",":")))
if __name__=="__main__": main()
