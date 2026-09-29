"""Deterministic, synthetic SOC submissions. Ground truth stays outside the app DB."""
import argparse
import csv
import hashlib
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

SECTORS = ("Power", "Telecom", "Finance")
PACKS = {"smoke": (6, 10, 90, 3000, 600), "demo": (36, 15, 548, 40000, 8000)}
TABLES = {
 "entities": "cse_id TEXT PRIMARY KEY, sector TEXT, size_band TEXT, soc_model TEXT, operating_schedule TEXT",
 "assets": "asset_id TEXT PRIMARY KEY, cse_id TEXT, asset_type TEXT, criticality TEXT, source_id TEXT, commissioned_at TEXT, retired_at TEXT",
 "controls": "control_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, control_type TEXT, deployment_state TEXT, expected_source TEXT",
 "monitoring_expectations": "expectation_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, source_id TEXT, cadence TEXT, required_flag INTEGER, policy_basis TEXT",
 "telemetry_daily": "record_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, source_id TEXT, day TEXT, event_count INTEGER, heartbeat_count INTEGER, reporting_state TEXT",
 "alerts": "alert_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, category TEXT, severity TEXT, raised_at TEXT, acknowledged_at TEXT, disposition TEXT, source_user_id TEXT, observable TEXT",
 "cases": "case_id TEXT PRIMARY KEY, cse_id TEXT, alert_id TEXT, asset_id TEXT, opened_at TEXT, closed_at TEXT, status TEXT, severity TEXT, closure_reason TEXT, team_id TEXT",
 "case_alert_links": "link_id TEXT PRIMARY KEY, cse_id TEXT, case_id TEXT, alert_id TEXT, link_type TEXT",
 "investigation_steps": "step_id TEXT PRIMARY KEY, cse_id TEXT, case_id TEXT, step_type TEXT, completed_at TEXT, note_text TEXT, evidence_ref TEXT, source_user_id TEXT",
 "escalations": "escalation_id TEXT PRIMARY KEY, cse_id TEXT, case_id TEXT, raised_at TEXT, reviewed_at TEXT, decision TEXT",
 "remediations": "remediation_id TEXT PRIMARY KEY, cse_id TEXT, case_id TEXT, asset_id TEXT, status TEXT, completed_at TEXT, verification_ref TEXT",
 "source_users": "source_user_id TEXT PRIMARY KEY, cse_id TEXT, pseudonym TEXT, user_kind TEXT, role TEXT, team_id TEXT",
 "record_user_links": "link_id TEXT PRIMARY KEY, cse_id TEXT, source_user_id TEXT, record_type TEXT, record_id TEXT, relationship_role TEXT",
 "workflow_events": "event_id TEXT PRIMARY KEY, cse_id TEXT, case_id TEXT, activity TEXT, event_time TEXT, sequence_index INTEGER, source_user_id TEXT, evidence_ref TEXT",
 "threat_context": "context_id TEXT PRIMARY KEY, category TEXT, observable TEXT, valid_from TEXT, valid_to TEXT, source_snapshot TEXT, source_confidence TEXT",
 "vulnerability_context": "context_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, severity TEXT, applicability TEXT, observed_at TEXT",
 "service_context": "context_id TEXT PRIMARY KEY, cse_id TEXT, asset_id TEXT, start_at TEXT, end_at TEXT, reason TEXT, approved_by_role TEXT",
 "policy_requirements": "policy_id TEXT PRIMARY KEY, version TEXT, severity_scope TEXT, required_steps TEXT, escalation_rule TEXT, time_limit_hours REAL, effective_from TEXT",
 "teams": "team_id TEXT PRIMARY KEY, cse_id TEXT, role_mix TEXT, scheduled_hours INTEGER, effective_from TEXT",
 "coverage_mappings": "mapping_id TEXT PRIMARY KEY, technique_id TEXT, category TEXT, expected_source TEXT, asset_applicability TEXT, version TEXT",
 "submissions": "submission_id TEXT PRIMARY KEY, period_start TEXT, period_end TEXT, source TEXT, status TEXT, created_at TEXT, manifest_json TEXT, scan_json TEXT",
 "runs": "run_id TEXT PRIMARY KEY, submission_id TEXT, started_at TEXT, finished_at TEXT, status TEXT, engine_json TEXT, summary_json TEXT",
 "findings": "finding_id TEXT PRIMARY KEY, run_id TEXT, cse_id TEXT, asset_id TEXT, case_id TEXT, family TEXT, title TEXT, description TEXT, priority TEXT, confidence TEXT, queue TEXT, observed_json TEXT, expected_json TEXT, evidence_json TEXT, alternative TEXT, next_action TEXT, model_json TEXT",
 "decisions": "decision_id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT, reviewer TEXT, decision TEXT, reason TEXT, created_at TEXT",
 "audit": "audit_id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, detail_json TEXT, created_at TEXT, previous_hash TEXT, event_hash TEXT",
 "users": "username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, active INTEGER",
 "sessions": "token_hash TEXT PRIMARY KEY, username TEXT, expires_at TEXT",
 "event_sessions": "session_id TEXT PRIMARY KEY, run_id TEXT, cse_id TEXT, asset_id TEXT, source_id TEXT, source_user_id TEXT, started_at TEXT, ended_at TEXT, member_count INTEGER, member_ids_json TEXT, gap_minutes INTEGER",
 "quality_issues": "issue_id INTEGER PRIMARY KEY AUTOINCREMENT, submission_id TEXT, table_name TEXT, record_ref TEXT, issue TEXT, severity TEXT",
}

def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    for table, columns in TABLES.items():
        db.execute(f"CREATE TABLE IF NOT EXISTS {table} ({columns})")
    db.commit()
    return db

def iso(dt): return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")

def rows(db, table, records):
    if not records: return
    keys = list(records[0])
    db.executemany(f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})", [tuple(row[k] for k in keys) for row in records])

def generate(db_path, out_dir, pack="smoke", seed=42):
    rng = random.Random(seed)
    n_cse, assets_each, days, n_alerts, n_cases = PACKS[pack]
    end = datetime(2026, 8, 31, tzinfo=timezone.utc)
    start = end - timedelta(days=days - 1)
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    db = connect(db_path)
    if db.execute("SELECT count(*) FROM entities").fetchone()[0]:
        return {"status":"existing", "db":str(db_path)}
    tables = {name: [] for name in TABLES if name not in ("submissions","runs","findings","decisions","audit","users","sessions","quality_issues")}
    truth = []
    entity_ids = []
    for i in range(n_cse):
        sector = SECTORS[i % 3]
        cse = f"CSE-{sector.upper()}-{i//3+1:03d}"
        entity_ids.append(cse)
        tables["entities"].append(dict(cse_id=cse, sector=sector, size_band="medium" if i%3 else "large", soc_model="in-house" if i%2 else "managed", operating_schedule="24x7"))
        tables["teams"].append(dict(team_id=f"{cse}-TEAM",cse_id=cse,role_mix="analyst,lead",scheduled_hours=168,effective_from=iso(start)))
        for u in range(5):
            uid=f"{cse}-USR-{u+1:02d}"
            tables["source_users"].append(dict(source_user_id=uid,cse_id=cse,pseudonym=f"Analyst {u+1:02d}",user_kind="analyst",role="SOC analyst",team_id=f"{cse}-TEAM"))
        for a in range(assets_each):
            asset = f"{cse}-A{a+1:03d}"
            criticality = "critical" if a%5==0 else "high" if a%3==0 else "standard"
            source = "endpoint-events" if a%2 else "identity-logs"
            tables["assets"].append(dict(asset_id=asset,cse_id=cse,asset_type="OT gateway" if a%4==0 else "server",criticality=criticality,source_id=source,commissioned_at=iso(start-timedelta(days=20)),retired_at=None))
            tables["controls"].append(dict(control_id=f"CTL-{asset}",cse_id=cse,asset_id=asset,control_type="event monitoring",deployment_state="deployed",expected_source=source))
            tables["monitoring_expectations"].append(dict(expectation_id=f"EXP-{asset}",cse_id=cse,asset_id=asset,source_id=source,cadence="daily",required_flag=1,policy_basis="DEMO-POLICY-1"))
            gap = a==0 and i%3==0
            maintenance = a==1 and i%3==0
            for d in range(days):
                day = (start+timedelta(days=d)).date().isoformat()
                if gap and d>=days-12:
                    count=0; heartbeat=0; state="explicit_zero"
                elif maintenance and days-8<=d<days-3:
                    count=0; heartbeat=0; state="approved_inactive"
                else:
                    count=rng.randrange(12,90); heartbeat=1; state="reported"
                tables["telemetry_daily"].append(dict(record_id=f"T-{asset}-{day}",cse_id=cse,asset_id=asset,source_id=source,day=day,event_count=count,heartbeat_count=heartbeat,reporting_state=state))
            if maintenance:
                tables["service_context"].append(dict(context_id=f"M-{asset}",cse_id=cse,asset_id=asset,start_at=iso(start+timedelta(days=days-8)),end_at=iso(start+timedelta(days=days-3)),reason="approved maintenance",approved_by_role="operations manager"))
            if gap: truth.append(dict(family="monitoring_gap",cse_id=cse,asset_id=asset,case_id=None))
    for j in range(n_alerts):
        cse=entity_ids[j%n_cse]; asset=f"{cse}-A{rng.randrange(1,assets_each+1):03d}"
        raised=start+timedelta(days=rng.randrange(days),hours=rng.randrange(24),minutes=rng.randrange(60))
        sev="critical" if j%17==0 else "high" if j%5==0 else "medium"
        uid=f"{cse}-USR-{j%5+1:02d}"
        alert=f"ALRT-{j+1:06d}"
        tables["alerts"].append(dict(alert_id=alert,cse_id=cse,asset_id=asset,category=("identity","execution","defence-evasion")[j%3],severity=sev,raised_at=iso(raised),acknowledged_at=iso(raised+timedelta(minutes=rng.randrange(5,80))),disposition="closed",source_user_id=uid,observable=f"TEST-{j%23:03d}"))
        tables["record_user_links"].append(dict(link_id=f"L-{alert}",cse_id=cse,source_user_id=uid,record_type="alert",record_id=alert,relationship_role="analyst"))
    for j in range(n_cases):
        alert=tables["alerts"][j*max(1,n_alerts//n_cases)]
        cse=alert["cse_id"]; asset=alert["asset_id"]; uid=alert["source_user_id"]
        opened=datetime.fromisoformat(alert["raised_at"].replace("Z","+00:00"))
        injected=(j%29==0 and alert["severity"]=="critical") or j==141
        severity="critical" if j==141 else alert["severity"]
        duration=0.35 if injected else rng.uniform(4,30)
        closed=opened+timedelta(hours=duration)
        case=f"CASE-DEMO-{j+1:04d}"
        tables["cases"].append(dict(case_id=case,cse_id=cse,alert_id=alert["alert_id"],asset_id=asset,opened_at=iso(opened),closed_at=iso(closed),status="closed",severity=severity,closure_reason="review completed" if not injected else "resolved",team_id=f"{cse}-TEAM"))
        tables["case_alert_links"].append(dict(link_id=f"CAL-{case}",cse_id=cse,case_id=case,alert_id=alert["alert_id"],link_type="primary"))
        steps=[("acknowledge",opened+timedelta(minutes=10)),("investigate",opened+timedelta(hours=duration/2)),("close",closed)]
        if injected: steps=[steps[0],steps[-1]]
        for k,(activity,ts) in enumerate(steps):
            event=f"EV-{case}-{k}"
            tables["workflow_events"].append(dict(event_id=event,cse_id=cse,case_id=case,activity=activity,event_time=iso(ts),sequence_index=k,source_user_id=uid,evidence_ref=f"workflow_events.csv#{event}"))
            if activity=="investigate":
                tables["investigation_steps"].append(dict(step_id=f"STEP-{case}",cse_id=cse,case_id=case,step_type="investigate",completed_at=iso(ts),note_text="Reviewed alert context and linked endpoint records.",evidence_ref=f"alerts.csv#{alert['alert_id']}",source_user_id=uid))
        if severity=="critical" and not injected:
            tables["escalations"].append(dict(escalation_id=f"ESC-{case}",cse_id=cse,case_id=case,raised_at=iso(opened+timedelta(minutes=25)),reviewed_at=iso(opened+timedelta(hours=2)),decision="reviewed"))
        if j%6==0 and not injected:
            tables["remediations"].append(dict(remediation_id=f"REM-{case}",cse_id=cse,case_id=case,asset_id=asset,status="verified",completed_at=iso(closed+timedelta(hours=4)),verification_ref=f"cases.csv#{case}"))
        tables["record_user_links"].append(dict(link_id=f"L-{case}",cse_id=cse,source_user_id=uid,record_type="case",record_id=case,relationship_role="handler"))
        if injected: truth.append(dict(family="missing_escalation",cse_id=cse,asset_id=asset,case_id=case))
    tables["threat_context"]=[dict(context_id="CTX-DEMO-1",category="identity",observable="TEST-007",valid_from=iso(start),valid_to=iso(end+timedelta(days=1)),source_snapshot="synthetic-fixture-1",source_confidence="medium"),dict(context_id="CTX-EXPIRED",category="execution",observable="TEST-010",valid_from=iso(start-timedelta(days=60)),valid_to=iso(start-timedelta(days=1)),source_snapshot="synthetic-fixture-1",source_confidence="low")]
    tables["vulnerability_context"]=[dict(context_id="VULN-DEMO-1",cse_id=entity_ids[0],asset_id=f"{entity_ids[0]}-A001",severity="high",applicability="applicable",observed_at=iso(end-timedelta(days=5)))]
    tables["policy_requirements"]=[dict(policy_id="DEMO-POLICY-1",version="1",severity_scope="critical",required_steps="acknowledge,investigate,close",escalation_rule="required",time_limit_hours=4,effective_from=iso(start))]
    tables["coverage_mappings"]=[dict(mapping_id="MAP-DEMO-1",technique_id="T1078",category="identity",expected_source="identity-logs",asset_applicability="server",version="1"),dict(mapping_id="MAP-DEMO-2",technique_id="T1059",category="execution",expected_source="endpoint-events",asset_applicability="server",version="1")]
    manifest={"schema_version":"1","pack":pack,"seed":seed,"synthetic":True,"period_start":iso(start),"period_end":iso(end),"table_counts":{k:len(v) for k,v in tables.items()},"generator_version":"1"}
    db.execute("INSERT INTO submissions VALUES (?,?,?,?,?,?,?,?)",("SUB-DEMO-1",manifest["period_start"],manifest["period_end"],"internal synthetic generator","ready",iso(datetime.now(timezone.utc)),json.dumps(manifest),json.dumps({"status":"internal_generated","note":"No external file was parsed"})))
    for table, records in tables.items(): rows(db,table,records)
    db.commit()
    for table, records in tables.items():
        if not records: continue
        with (out/f"{table}.csv").open("w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=list(records[0])); writer.writeheader(); writer.writerows(records)
        manifest.setdefault("sha256",{})[f"{table}.csv"]=hashlib.sha256((out/f"{table}.csv").read_bytes()).hexdigest()
    (out/"submission_manifest.json").write_text(json.dumps(manifest,indent=2))
    private=out.parent.parent/"evaluation_private"; private.mkdir(parents=True,exist_ok=True)
    (private/"ground_truth_scenarios.jsonl").write_text("".join(json.dumps(x)+"\n" for x in truth))
    db.execute("UPDATE submissions SET manifest_json=? WHERE submission_id='SUB-DEMO-1'",(json.dumps(manifest),)); db.commit(); db.close()
    return manifest

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--config",default="smoke",choices=PACKS); p.add_argument("--seed",type=int,default=42); p.add_argument("--db",default="data/prahari.sqlite"); p.add_argument("--out",default="data/demo")
    a=p.parse_args(); print(json.dumps(generate(a.db,a.out,a.config,a.seed),indent=2))
