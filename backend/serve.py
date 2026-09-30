"""Loopback-only API and local UI for PRAHARI-SAT-SA."""
import argparse
import base64
import csv
import hashlib
import hmac
import html
import io
import json
import os
import secrets
import shutil
import sqlite3
import sys
import subprocess
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Cookie, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Keep direct launches (`python backend/serve.py`) working as well as
# module launches (`python -m backend.serve`).
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from analytics.run import run as analyse
from generator.build import TABLES, connect, generate

DB=Path(os.getenv("PRAHARI_DB",str(ROOT/"data/demo.sqlite")))
DEMO=ROOT/"data/demo"
app=FastAPI(title="PRAHARI-SAT-SA",docs_url=None,redoc_url=None,openapi_url=None)

def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def query(sql,args=()):
    with connect(DB) as db: return [dict(x) for x in db.execute(sql,args)]
def one(sql,args=()):
    result=query(sql,args); return result[0] if result else None
def hash_password(password,salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,300000)
    return base64.b64encode(salt).decode()+":"+base64.b64encode(digest).decode()
def verify_password(password,stored):
    try:
        s,d=stored.split(":"); salt=base64.b64decode(s)
        return hmac.compare_digest(hash_password(password,salt),stored)
    except Exception: return False
def audit(db,actor,action,detail):
    previous=db.execute("SELECT event_hash FROM audit ORDER BY audit_id DESC LIMIT 1").fetchone()
    prev=previous[0] if previous else "GENESIS"
    created=now()
    payload=json.dumps({"actor":actor,"action":action,"detail":detail,"created_at":created,"previous_hash":prev},sort_keys=True)
    digest=hashlib.sha256(payload.encode()).hexdigest()
    db.execute("INSERT INTO audit (actor,action,detail_json,created_at,previous_hash,event_hash) VALUES (?,?,?,?,?,?)",(actor,action,json.dumps(detail),created,prev,digest))

def current_user(sid=None):
    if not sid: raise HTTPException(401,"Sign in required")
    record=one("SELECT u.username,u.role,s.expires_at FROM sessions s JOIN users u ON s.username=u.username WHERE token_hash=? AND u.active=1",(hashlib.sha256(sid.encode()).hexdigest(),))
    if not record or record["expires_at"]<now(): raise HTTPException(401,"Session expired")
    return record
def require(sid,roles=None):
    user=current_user(sid)
    if roles and user["role"] not in roles: raise HTTPException(403,"Role does not permit this action")
    return user
def parse_finding(row):
    for key in ("observed_json","expected_json","evidence_json","model_json"):
        row[key[:-5]]=json.loads(row.pop(key) or "{}")
    return row

@app.on_event("startup")
def startup():
    DB.parent.mkdir(parents=True,exist_ok=True)
    db=connect(DB)
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        password=os.getenv("PRAHARI_ADMIN_PASSWORD","1234")
        db.execute("INSERT INTO users VALUES (?,?,?,1)",(os.getenv("PRAHARI_ADMIN_USER","supervisor"),hash_password(password),"administrator"))
    else:
        demo_user=db.execute("SELECT password_hash FROM users WHERE username='supervisor'").fetchone()
        if demo_user and verify_password("Demo@157Change",demo_user["password_hash"]):
            db.execute("UPDATE users SET password_hash=? WHERE username='supervisor'",(hash_password(os.getenv("PRAHARI_ADMIN_PASSWORD","1234")),))
    db.commit()
    if not db.execute("SELECT 1 FROM entities LIMIT 1").fetchone():
        db.close(); generate(DB,DEMO,"smoke",42); db=connect(DB)
    if not db.execute("SELECT 1 FROM runs WHERE status LIKE 'completed%' LIMIT 1").fetchone():
        db.close(); analyse(DB); db=connect(DB)
    db.commit(); db.close()

class Login(BaseModel): username:str; password:str
class Decision(BaseModel): decision:str; reason:str=""

@app.post("/api/login")
def login(body:Login,response:Response):
    row=one("SELECT * FROM users WHERE username=? AND active=1",(body.username,))
    if not row or not verify_password(body.password,row["password_hash"]): raise HTTPException(401,"Invalid credentials")
    token=secrets.token_urlsafe(32); expiry=(datetime.now(timezone.utc)+timedelta(hours=8)).isoformat().replace("+00:00","Z")
    with connect(DB) as db:
        db.execute("INSERT INTO sessions VALUES (?,?,?)",(hashlib.sha256(token.encode()).hexdigest(),body.username,expiry))
        audit(db,body.username,"login",{})
    response.set_cookie("sid",token,httponly=True,samesite="strict",secure=False,max_age=28800)
    return {"username":body.username,"role":row["role"]}

@app.post("/api/logout")
def logout(response:Response,sid:str|None=Cookie(default=None)):
    user=require(sid)
    with connect(DB) as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(sid.encode()).hexdigest(),))
        audit(db,user["username"],"logout",{})
    response.delete_cookie("sid"); return {"ok":True}

@app.get("/api/me")
def me(sid:str|None=Cookie(default=None)): return require(sid)

@app.get("/api/overview")
def overview(sid:str|None=Cookie(default=None)):
    require(sid)
    active=one("SELECT * FROM runs WHERE status LIKE 'completed%' ORDER BY started_at DESC LIMIT 1")
    if not active: return {"run":None}
    summary=json.loads(active["summary_json"] or "{}")
    entities=query("SELECT e.cse_id,e.sector,e.size_band,e.soc_model,count(f.finding_id) finding_count,sum(CASE WHEN f.priority='high' THEN 1 ELSE 0 END) high_count,sum(CASE WHEN f.queue='data_attention' THEN 1 ELSE 0 END) data_count FROM entities e LEFT JOIN findings f ON e.cse_id=f.cse_id AND f.run_id=? GROUP BY e.cse_id ORDER BY high_count DESC,finding_count DESC",(active["run_id"],))
    for e in entities:
        e["indicator"]=min(100,(e["high_count"] or 0)*12+(e["finding_count"] or 0)*3)
    families=query("SELECT family,count(*) n FROM findings WHERE run_id=? GROUP BY family ORDER BY n DESC",(active["run_id"],))
    trend=query("SELECT substr(opened_at,1,7) month,count(*) cases FROM cases GROUP BY month ORDER BY month")
    priorities=query("SELECT finding_id,cse_id,title,priority,confidence,queue,family FROM findings WHERE run_id=? ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,finding_id LIMIT 8",(active["run_id"],))
    return {"run":{**active,"engine":json.loads(active["engine_json"]),"summary":summary},"entities":entities,"families":families,"trend":trend,"priorities":priorities,"sectors":query("SELECT sector,count(*) entities FROM entities GROUP BY sector")}

@app.get("/api/entities")
def entities(sector:str="",sid:str|None=Cookie(default=None)):
    require(sid)
    sql="SELECT e.*,count(f.finding_id) findings,sum(CASE WHEN f.priority='high' THEN 1 ELSE 0 END) high_findings FROM entities e LEFT JOIN findings f ON e.cse_id=f.cse_id AND f.run_id=(SELECT run_id FROM runs WHERE status LIKE 'completed%' ORDER BY started_at DESC LIMIT 1)"
    args=[]
    if sector: sql+=" WHERE e.sector=?"; args=[sector]
    return query(sql+" GROUP BY e.cse_id ORDER BY high_findings DESC,e.cse_id",args)

@app.get("/api/entities/{cse_id}")
def entity(cse_id:str,sid:str|None=Cookie(default=None)):
    require(sid)
    e=one("SELECT * FROM entities WHERE cse_id=?",(cse_id,))
    if not e: raise HTTPException(404,"Entity not found")
    assets=query("SELECT a.*,sum(CASE WHEN t.heartbeat_count=0 AND t.reporting_state='explicit_zero' THEN 1 ELSE 0 END) zero_days FROM assets a LEFT JOIN telemetry_daily t ON a.asset_id=t.asset_id WHERE a.cse_id=? GROUP BY a.asset_id ORDER BY zero_days DESC",(cse_id,))
    findings=[parse_finding(x) for x in query("SELECT * FROM findings WHERE cse_id=? AND run_id=(SELECT run_id FROM runs WHERE status LIKE 'completed%' ORDER BY started_at DESC LIMIT 1) ORDER BY CASE priority WHEN 'high' THEN 0 ELSE 1 END LIMIT 100",(cse_id,))]
    peers=query("SELECT cse_id FROM entities WHERE sector=? AND cse_id<>?",(e["sector"],cse_id))
    monthly=query("SELECT substr(opened_at,1,7) month,count(*) cases FROM cases WHERE cse_id=? GROUP BY month ORDER BY month",(cse_id,))
    dimensions={"Detection":sum(f["family"] in ("monitoring_gap","peer_deviation") for f in findings),"Investigation":sum(f["family"] in ("premature_closure","case_shape_outlier") for f in findings),"Escalation":sum(f["family"]=="missing_escalation" for f in findings),"Process":sum(f["family"]=="process_conformance" for f in findings),"Data quality":sum(f["queue"]=="data_attention" for f in findings),"Remediation":0}
    return {"entity":e,"assets":assets,"findings":findings,"peer_members":[x["cse_id"] for x in peers],"peer_eligible":len(peers)>=6,"trend":monthly,"dimensions":dimensions}

@app.get("/api/findings")
def findings(queue:str="",priority:str="",sector:str="",q:str="",limit:int=200,sid:str|None=Cookie(default=None)):
    require(sid)
    sql="SELECT f.*,e.sector,(SELECT decision FROM decisions d WHERE d.finding_id=f.finding_id ORDER BY decision_id DESC LIMIT 1) review_status FROM findings f JOIN entities e ON e.cse_id=f.cse_id WHERE f.run_id=(SELECT run_id FROM runs WHERE status LIKE 'completed%' ORDER BY started_at DESC LIMIT 1)"; args=[]
    if queue: sql+=" AND f.queue=?"; args.append(queue)
    if priority: sql+=" AND f.priority=?"; args.append(priority)
    if sector: sql+=" AND e.sector=?"; args.append(sector)
    if q: sql+=" AND (f.title LIKE ? OR f.cse_id LIKE ? OR f.case_id LIKE ? OR f.asset_id LIKE ?)"; args += [f"%{q}%"]*4
    sql+=" ORDER BY CASE f.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,f.finding_id LIMIT ?"; args.append(min(max(limit,1),500))
    return [parse_finding(x) for x in query(sql,args)]

@app.get("/api/findings/{finding_id}")
def finding(finding_id:str,sid:str|None=Cookie(default=None)):
    require(sid)
    f=one("SELECT * FROM findings WHERE finding_id=?",(finding_id,))
    if not f: raise HTTPException(404,"Finding not found")
    f=parse_finding(f)
    related={}
    if f["case_id"]:
        for table in ("cases","case_alert_links","workflow_events","investigation_steps","escalations","remediations","record_user_links"):
            column="record_id" if table=="record_user_links" else "case_id"
            related[table]=query(f"SELECT * FROM {table} WHERE {column}=?",(f["case_id"],))
    if f["asset_id"]:
        related["asset"]=one("SELECT * FROM assets WHERE asset_id=?",(f["asset_id"],))
        related["telemetry_recent"]=query("SELECT * FROM telemetry_daily WHERE asset_id=? ORDER BY day DESC LIMIT 15",(f["asset_id"],))
        related["event_sessions"]=query("SELECT * FROM event_sessions WHERE asset_id=? AND run_id=? ORDER BY started_at DESC LIMIT 8",(f["asset_id"],f["run_id"]))
    if f["case_id"]:
        related["source_users"]=query("SELECT u.* FROM source_users u JOIN record_user_links l ON u.source_user_id=l.source_user_id WHERE l.record_id=?",(f["case_id"],))
    related["attack_mapping"]=json.loads((ROOT/"configs/attack_reference.json").read_text())
    related["decisions"]=query("SELECT reviewer,decision,reason,created_at FROM decisions WHERE finding_id=? ORDER BY decision_id DESC",(finding_id,))
    return {"finding":f,"related":related}

@app.post("/api/findings/{finding_id}/decision")
def decide(finding_id:str,body:Decision,sid:str|None=Cookie(default=None)):
    user=require(sid,["administrator","supervisor","reviewer"])
    allowed={"confirmed concern","dismissed","needs more evidence","deferred","duplicate","resolved with evidence"}
    if body.decision not in allowed: raise HTTPException(422,"Invalid decision")
    if body.decision in {"confirmed concern","dismissed","resolved with evidence"} and not body.reason.strip(): raise HTTPException(422,"Reason required")
    if not one("SELECT finding_id FROM findings WHERE finding_id=?",(finding_id,)): raise HTTPException(404,"Finding not found")
    with connect(DB) as db:
        db.execute("INSERT INTO decisions (finding_id,reviewer,decision,reason,created_at) VALUES (?,?,?,?,?)",(finding_id,user["username"],body.decision,body.reason.strip(),now()))
        audit(db,user["username"],"review_decision",{"finding_id":finding_id,"decision":body.decision,"reason":body.reason.strip()})
    return {"ok":True}

@app.get("/api/quality")
def quality(sid:str|None=Cookie(default=None)):
    require(sid)
    return {"submissions":query("SELECT * FROM submissions ORDER BY created_at DESC"),"issues":query("SELECT * FROM quality_issues ORDER BY issue_id DESC LIMIT 100"),"scanner_available":bool(shutil.which("clamscan")),"check_availability":{"case_rules":bool(one("SELECT 1 FROM cases LIMIT 1")),"asset_coverage":bool(one("SELECT 1 FROM monitoring_expectations LIMIT 1")),"escalation":bool(one("SELECT 1 FROM escalations LIMIT 1")),"process_conformance":bool(one("SELECT 1 FROM workflow_events LIMIT 1"))}}

@app.get("/api/runs")
def runs(sid:str|None=Cookie(default=None)):
    require(sid)
    return [{**r,"engine":json.loads(r["engine_json"]),"summary":json.loads(r["summary_json"])} for r in query("SELECT * FROM runs ORDER BY started_at DESC LIMIT 30")]

@app.post("/api/runs")
def new_run(sid:str|None=Cookie(default=None)):
    user=require(sid,["administrator","supervisor"])
    result=analyse(DB)
    with connect(DB) as db: audit(db,user["username"],"analysis_run",{"run_id":result["run_id"]})
    return result

@app.get("/api/audit")
def audits(sid:str|None=Cookie(default=None)):
    require(sid,["administrator"])
    return query("SELECT * FROM audit ORDER BY audit_id DESC LIMIT 100")

@app.get("/api/report/{format}")
def report(format:str,sid:str|None=Cookie(default=None)):
    user=require(sid,["administrator","supervisor"])
    findings=query("SELECT finding_id,cse_id,asset_id,case_id,family,title,description,priority,confidence,queue,evidence_json FROM findings WHERE run_id=(SELECT run_id FROM runs WHERE status LIKE 'completed%' ORDER BY started_at DESC LIMIT 1)")
    summary=overview(sid)["run"]["summary"]
    with connect(DB) as db: audit(db,user["username"],"export_report",{"format":format,"findings":len(findings)})
    if format=="json": return JSONResponse({"notice":"SYNTHETIC DEMONSTRATION DATA — not an official assessment","summary":summary,"findings":findings},headers={"Content-Disposition":"attachment; filename=prahari-findings.json"})
    if format=="csv":
        buf=io.StringIO(); w=csv.DictWriter(buf,fieldnames=findings[0].keys() if findings else ["finding_id"]); w.writeheader()
        for row in findings:
            w.writerow({k:("'"+str(v) if isinstance(v,str) and v[:1] in ("=","+","-","@") else v) for k,v in row.items()})
        return Response(buf.getvalue(),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=prahari-findings.csv"})
    if format in ("html","zip"):
        body="".join(f"<tr><td>{html.escape(str(f['finding_id']))}</td><td>{html.escape(str(f['cse_id']))}</td><td>{html.escape(str(f['title']))}</td><td>{html.escape(str(f['priority']))}</td><td>{html.escape(str(f['confidence']))}</td></tr>" for f in findings)
        content=f"<!doctype html><html><head><meta charset='utf-8'><title>PRAHARI report</title><style>body{{font:15px Arial;max-width:1050px;margin:45px auto;color:#173047}}h1{{border-bottom:4px solid #df8736;padding-bottom:12px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}.notice{{padding:12px;background:#fff2df}}</style></head><body><h1>PRAHARI-SAT-SA · Assessment report</h1><p class='notice'>SYNTHETIC DEMONSTRATION DATA — provisional supervisory indicators, not an official assessment.</p><p>{len(findings)} findings across {summary.get('entities',0)} synthetic entities. Review all evidence and limitations before action.</p><table><thead><tr><th>ID</th><th>Entity</th><th>Finding</th><th>Priority</th><th>Confidence</th></tr></thead><tbody>{body}</tbody></table><p>Policy: DEMO-POLICY-1. Findings require human confirmation.</p></body></html>"
        if format=="html": return HTMLResponse(content,headers={"Content-Disposition":"attachment; filename=prahari-report.html"})
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED) as archive:
            payload=json.dumps({"notice":"SYNTHETIC DEMONSTRATION DATA","summary":summary,"findings":findings},indent=2).encode()
            report_bytes=content.encode()
            archive.writestr("report.html",report_bytes)
            archive.writestr("findings.json",payload)
            archive.writestr("hash_manifest.json",json.dumps({"report.html":hashlib.sha256(report_bytes).hexdigest(),"findings.json":hashlib.sha256(payload).hexdigest()},indent=2))
        return Response(output.getvalue(),media_type="application/zip",headers={"Content-Disposition":"attachment; filename=prahari-evidence.zip"})
    raise HTTPException(404,"Unsupported report format")

@app.post("/api/import")
async def import_package(file:UploadFile=File(...),sid:str|None=Cookie(default=None)):
    user=require(sid,["administrator"])
    raw=await file.read(25_000_001)
    if len(raw)>25_000_000: raise HTTPException(413,"Package exceeds 25 MB")
    if not raw.startswith(b"PK\x03\x04"): raise HTTPException(415,"Upload a ZIP package of allowlisted CSV/JSON tables")
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/"submission.zip"; path.write_bytes(raw)
        scanner=shutil.which("clamscan")
        if not scanner:
            with connect(DB) as db: audit(db,user["username"],"import_blocked",{"reason":"scanner_unavailable","sha256":hashlib.sha256(raw).hexdigest()})
            raise HTTPException(503,"Offline ClamAV scanner unavailable. Import blocked before parsing.")
        try: scan=subprocess.run([scanner,"--no-summary",str(path)],capture_output=True,text=True,timeout=60)
        except subprocess.TimeoutExpired:
            raise HTTPException(503,"Scanner timeout. Import blocked.")
        receipt={"status":"clean" if scan.returncode==0 else "detected" if scan.returncode==1 else "scan_error","output":scan.stdout[-500:],"sha256":hashlib.sha256(raw).hexdigest(),"scanned_at":now()}
        if scan.returncode!=0:
            with connect(DB) as db: audit(db,user["username"],"import_blocked",receipt)
            raise HTTPException(422,f"Scanner did not clear package: {receipt['status']}")
        with zipfile.ZipFile(path) as archive:
            members=archive.infolist()
            if len(members)>30 or sum(x.file_size for x in members)>80_000_000: raise HTTPException(413,"Expanded package too large")
            for m in members:
                if "/" in m.filename or "\\" in m.filename or m.filename.startswith("."): raise HTTPException(422,"Nested or unsafe paths are not allowed")
            accepted={}; issues=[]
            for m in members:
                name=m.filename; stem=Path(name).stem; suffix=Path(name).suffix.lower()
                if suffix in (".sqlite",".db"):
                    try:
                        sqlite_path=Path(tmp)/"readonly.sqlite"; sqlite_path.write_bytes(archive.read(m))
                        source=sqlite3.connect(f"file:{sqlite_path}?mode=ro",uri=True)
                        source.row_factory=sqlite3.Row
                        source.execute("PRAGMA query_only=ON")
                        for table in ("entities","assets","controls","monitoring_expectations","telemetry_daily","alerts","cases","case_alert_links","investigation_steps","escalations","remediations","source_users","record_user_links","workflow_events","threat_context","vulnerability_context","service_context","policy_requirements","teams","coverage_mappings"):
                            if source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():
                                accepted[table]=[dict(row) for row in source.execute(f"SELECT * FROM {table}")]
                        source.close()
                    except sqlite3.DatabaseError as exc: issues.append({"table":"sqlite_export","issue":str(exc)})
                    continue
                if stem not in TABLES or stem in {"users","sessions","event_sessions","audit","runs","findings","decisions","quality_issues","submissions"} or suffix not in (".csv",".json",".jsonl"): continue
                data=archive.read(m)
                try:
                    records=list(csv.DictReader(io.StringIO(data.decode("utf-8-sig")))) if suffix==".csv" else [json.loads(line) for line in data.decode("utf-8-sig").splitlines() if line.strip()] if suffix==".jsonl" else json.loads(data)
                    if not isinstance(records,list): raise ValueError("Expected JSON array")
                    allowed={part.strip().split()[0] for part in TABLES[stem].split(",")}
                    accepted[stem]=[{k:r.get(k) for k in allowed if k in r} for r in records if isinstance(r,dict)]
                    if len(accepted[stem])!=len(records): issues.append({"table":stem,"issue":"Non-object rows skipped"})
                except (UnicodeError,ValueError,csv.Error) as exc: issues.append({"table":stem,"issue":str(exc)})
            if "entities" not in accepted or "alerts" not in accepted: raise HTTPException(422,"entities and alerts are essential tables")
            submission=f"SUB-{secrets.token_hex(4).upper()}"
            with connect(DB) as db:
                try:
                    for table,records in accepted.items():
                        for index,row in enumerate(records):
                            keys=list(row)
                            try: db.execute(f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})",tuple(row.values()))
                            except sqlite3.IntegrityError as exc: issues.append({"table":table,"record":str(index+1),"issue":str(exc)})
                    status="partial" if issues else "ready"
                    db.execute("INSERT INTO submissions VALUES (?,?,?,?,?,?,?,?)",(submission,None,None,"offline upload",status,now(),json.dumps({"synthetic":False,"table_counts":{k:len(v) for k,v in accepted.items()}}),json.dumps(receipt)))
                    for issue in issues: db.execute("INSERT INTO quality_issues (submission_id,table_name,record_ref,issue,severity) VALUES (?,?,?,?,?)",(submission,issue["table"],issue.get("record","file"),issue["issue"],"warning"))
                    audit(db,user["username"],"import_package",{"submission":submission,"status":status,"issues":len(issues)})
                except Exception: db.rollback(); raise
            return {"submission_id":submission,"status":status,"issues":issues,"scan":receipt}

DIST=ROOT/"frontend/dist"
if DIST.exists(): app.mount("/assets",StaticFiles(directory=DIST/"assets"),name="assets")

@app.get("/{path:path}")
def frontend(path:str):
    target=DIST/path
    if path and target.is_file() and DIST in target.resolve().parents: return FileResponse(target)
    index=DIST/"index.html"
    if index.exists(): return FileResponse(index)
    return HTMLResponse("Frontend is not built. Run npm install and npm run build in frontend/.",status_code=503)

if __name__=="__main__":
    a=argparse.ArgumentParser(); a.add_argument("--host",default="127.0.0.1"); a.add_argument("--port",type=int,default=8000); args=a.parse_args()
    import uvicorn
    uvicorn.run("backend.serve:app",host=args.host,port=args.port,reload=False)
