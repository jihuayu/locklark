"""Private synthetic 1PUX notes material and ordinary interactive CLI operations."""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import zipfile

from personal_acceptance import invoke


class NotesFixtureFailure(Exception):
    pass


def write_archive(path, item):
    data={"accounts":[{"attrs":{"uuid":"notes-account"},"vaults":[{"attrs":{"uuid":"notes-vault"},"items":[item]}]}]}
    with zipfile.ZipFile(path,"w") as archive:
        archive.writestr("export.attributes",json.dumps({"version":3,"description":"1Password Unencrypted Export","createdAt":0}))
        archive.writestr("export.data",json.dumps(data,ensure_ascii=False))
    os.chmod(path,0o600)


def make_material(directory):
    directory=Path(directory);directory.mkdir(mode=0o700)
    entropy=os.urandom(40).hex()
    original="  合成多行备注🔐\n"+entropy[:24]+"\r\nsecond line\tkeep spaces  \n双向\u202e标记\n最后一行  \n"
    edited="  修改后的备注🌿\n"+entropy[24:48]+"\nline three stays separate\n尾部空格  \n"
    rejected="Cancelled synthetic notes\n"+entropy[48:]+"\n不应保存🔒\n"
    item={"uuid":"notes-first","categoryUuid":"001","state":"active","createdAt":123,
          "overview":{"title":"Notes imported login","url":"https://notes.locklark.test/login"},
          "details":{"notesPlain":original,"loginFields":[
              {"designation":"username","type":"T","value":"Notes-user-"+entropy[:16]},
              {"designation":"password","type":"P","value":"Notes-password-"+entropy[16:40]}]}}
    f={"Path":str(directory/"synthetic.ll"),"Password":"Notes-master-"+entropy[40:56],"Secret":"",
       "Username":item["details"]["loginFields"][0]["value"],"Value":item["details"]["loginFields"][1]["value"],
       "URL":item["overview"]["url"],"NotesOriginal":original,"NotesEdited":edited,"NotesRejected":rejected,
       "ExportPassword":"Notes-export-"+entropy[56:],"NotesConflict":"Independent-notes-"+entropy[12:40],"SourceItem":item,"Archive":str(directory/"notes.1pux"),
       "IDs":{},"OTPSeed":"","OTPConfig":"","ProviderValue":"","ProviderCanary":""}
    write_archive(f["Archive"],item)
    persist(directory/"fixture.json",f)
    return f


def persist(path,f):
    path=Path(path)
    with path.open("w",encoding="utf-8") as output:json.dump(f,output,ensure_ascii=False)
    path.chmod(0o600)


def initialize(binary,directory):
    f=make_material(directory)
    _,f["Secret"]=invoke(binary,"init",f["Path"],[("主密码",f["Password"]),("再次输入主密码",f["Password"]),
                       ("重新输入刚保存的 Secret Key",None)],issue=True)
    persist(Path(directory)/"fixture.json",f)
    return f


def factors(f):
    return [("主密码",f["Password"]),("Secret Key",f["Secret"])]


def import_notes(binary,directory,with_notes=True):
    f=initialize(binary,directory)
    if not with_notes:
        item=copy.deepcopy(f["SourceItem"]);item["details"].pop("notesPlain")
        write_archive(f["Archive"],item);f["SourceItem"]=item
        persist(Path(directory)/"fixture.json",f)
    private=(f["Password"],f["Secret"],f["Username"],f["Value"],f["NotesOriginal"])
    options=("--source",f["Archive"])
    plan,_=invoke(binary,"plan-import-1pux",f["Path"],factors(f)+[("输入 PLAN 确认生成导入计划","PLAN")],options=options,forbidden=private)
    profile="login-notes-v2" if with_notes else "login-v1"
    if plan["report"]["profile"]!=profile:raise NotesFixtureFailure()
    receipt,_=invoke(binary,"import-1pux",f["Path"],factors(f)+[("输入 SAVE 确认整批导入","SAVE")],
                     options=options+("--digest",plan["report"]["source_digest"]),forbidden=private)
    if receipt["status"]!="imported-"+profile:raise NotesFixtureFailure()
    rows,_=invoke(binary,"list",f["Path"],factors(f),forbidden=private)
    if len(rows)!=1 or rows[0]["title"]!="Notes imported login":raise NotesFixtureFailure()
    f["IDs"]["notes"]=rows[0]["id"]
    persist(Path(directory)/"fixture.json",f)
    return f


def baseline(binary,directory):
    f=initialize(binary,directory)
    invoke(binary,"plan-import-1pux",f["Path"],factors(f)+[("输入 PLAN 确认生成导入计划","PLAN")],
           options=("--source",f["Archive"]),ok=False,expect_error="unsupported 1PUX",
           forbidden=(f["NotesOriginal"],f["Username"],f["Value"]))
    rows,_=invoke(binary,"list",f["Path"],factors(f))
    if rows:raise NotesFixtureFailure()
    print("BASELINE RED: normal CLI rejects valid multiline login notes as unsupported; no items imported",flush=True)
    return 1


def check_export(fixture_path,exported,expected):
    from pykeepass import PyKeePass
    f=json.loads(Path(fixture_path).read_text())
    db=PyKeePass(str(exported),password=f["ExportPassword"])
    if len(db.entries)!=1:raise NotesFixtureFailure()
    entry=db.entries[0]
    notes={"original":f["NotesOriginal"],"edited":f["NotesEdited"],"empty":""}[expected]
    if (entry.notes or "")!=notes:raise NotesFixtureFailure()
    if notes and not entry._is_property_protected("Notes"):raise NotesFixtureFailure()
    if not notes and "Notes" in entry._get_string_field_keys():raise NotesFixtureFailure()
    if not entry.is_custom_property_protected("Locklark.ImportSource"):raise NotesFixtureFailure()
    provenance=json.loads(base64.b64decode(entry.get_custom_property("Locklark.ImportSource")))
    if provenance["item"]!=f["SourceItem"] or provenance["item"]["details"]["notesPlain"]!=f["NotesOriginal"]:raise NotesFixtureFailure()
    if entry.get_custom_property("Locklark.ID")!=f["IDs"]["notes"]:raise NotesFixtureFailure()
    print(json.dumps({"notes_exact":True,"protected_notes":bool(notes),"source_unchanged":True,"id_matches":True}))


if __name__=="__main__":
    try:
        if len(sys.argv)==4 and sys.argv[1]=="baseline":sys.exit(baseline(sys.argv[2],sys.argv[3]))
        if len(sys.argv)==5 and sys.argv[1]=="check":check_export(*sys.argv[2:]);sys.exit(0)
        raise NotesFixtureFailure()
    except Exception:
        print("FAIL: private login-notes fixture operation",file=sys.stderr);sys.exit(1)
