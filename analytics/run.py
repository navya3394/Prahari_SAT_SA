"""Evidence-first batch analytics. All conclusions are provisional for supervisor review."""
import argparse
import json
import math
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Keep direct launches (`python analytics/run.py`) working as well as
# module launches (`python -m analytics.run`).
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from generator.build import connect

POLICY = json.loads((ROOT/"configs/policy.json").read_text())
ATTACK = json.loads((ROOT/"configs/attack_reference.json").read_text())

def stamp(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def allrows(db, sql, args=()): return [dict(x) for x in db.execute(sql,args).fetchall()]
def j(v): return json.dumps(v,sort_keys=True)

def add_finding(db, run_id, *, cse_id, family, title, description, priority="medium", confidence="moderate", queue="concerns", asset_id=None, case_id=None, observed=None, expected=None, evidence=None, alternative="Work may be recorded in an approved source outside this submission.", next_action="Inspect the linked evidence and request clarification.", model=None):
    number=db.execute("SELECT count(*) FROM findings WHERE run_id=?",(run_id,)).fetchone()[0]+1
    db.execute("INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(f"F-{run_id}-{number:05d}",run_id,cse_id,asset_id,case_id,family,title,description,priority,confidence,queue,j(observed or {}),j(expected or {}),j(evidence or []),alternative,next_action,j(model or {})))

def run(db_path, submission_id="SUB-DEMO-1"):
    db=connect(db_path)
    submission=db.execute("SELECT * FROM submissions WHERE submission_id=? AND status IN ('ready','partial')",(submission_id,)).fetchone()
    if not submission: raise ValueError("Submission is not ready or does not exist")
    run_id=f"RUN-{db.execute('SELECT count(*) FROM runs').fetchone()[0]+1:04d}"
    engines={"rules":"completed","negative_space":"completed","peer":"completed","trend":"completed","case_anomaly":"not_run","process_conformance":"not_run","sessionisation":"not_run","duckdb_snapshot":"not_run"}
    db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?)",(run_id,submission_id,stamp(),None,"running",j(engines),"{}")); db.commit()
    try:
        cases=allrows(db,"SELECT * FROM cases")
        alerts=allrows(db,"SELECT * FROM alerts")
        assets={r["asset_id"]:r for r in allrows(db,"SELECT * FROM assets")}
        entities=allrows(db,"SELECT * FROM entities")
        steps=defaultdict(list); escalations=defaultdict(list); events=defaultdict(list)
        for r in allrows(db,"SELECT * FROM investigation_steps"): steps[r["case_id"]].append(r)
        for r in allrows(db,"SELECT * FROM escalations"): escalations[r["case_id"]].append(r)
        for r in allrows(db,"SELECT * FROM workflow_events ORDER BY event_time,sequence_index"): events[r["case_id"]].append(r)
        features=[]; feature_cases=[]
        alignments={}
        try:
            import pm4py
            from pm4py.objects.log.obj import EventLog,Trace,Event
            tree=pm4py.parse_process_tree("-> ( 'acknowledge', 'investigate', 'close' )")
            petri,initial,final=pm4py.convert_to_petri_net(tree)
            def alignment(activities):
                key=tuple(activities)
                if key not in alignments:
                    log=EventLog([Trace([Event({"concept:name":a}) for a in activities])])
                    alignments[key]=pm4py.conformance_diagnostics_alignments(log,petri,initial,final)[0]
                return alignments[key]
            engines["process_conformance"]="completed_pm4py_alignment"
        except ImportError:
            def alignment(activities): return {"alignment":[],"fitness":None,"note":"PM4Py unavailable"}
            engines["process_conformance"]="unavailable_dependency"
        for case in cases:
            cid=case["case_id"]; trace=events[cid]; activities=[e["activity"] for e in trace]
            evidence=[{"table":"cases","id":cid,"ref":f"cases.csv#{cid}"}]+[{"table":"workflow_events","id":e["event_id"],"ref":e["evidence_ref"]} for e in trace]
            closed=bool(case["closed_at"])
            hours=(datetime.fromisoformat(case["closed_at"].replace("Z","+00:00"))-datetime.fromisoformat(case["opened_at"].replace("Z","+00:00"))).total_seconds()/3600 if closed else None
            missing=[x for x in POLICY["required_steps"] if x not in activities] if closed else []
            diagnostic=alignment(activities) if closed and activities else {}
            if missing:
                add_finding(db,run_id,cse_id=case["cse_id"],asset_id=case["asset_id"],case_id=cid,family="process_conformance",title="Required workflow activity absent",description=f"Completed case trace omits {', '.join(missing)} under {POLICY['version']}.",priority="high" if case["severity"]=="critical" else "medium",observed={"trace":activities,"missing_activities":missing},expected={"sequence":POLICY["required_steps"],"policy_version":POLICY["version"]},evidence=evidence,next_action="Review the case timeline and any authorised workflow exception.",model={"engine":"PM4Py alignment" if engines["process_conformance"].startswith("completed") else "reference_trace","fit":diagnostic.get("fitness"),"alignment":diagnostic.get("alignment"),"model_version":"DEMO-PROCESS-1","note":"Trace fitness is not a probability of failure."})
            if case["severity"]=="critical" and closed and not escalations[cid]:
                add_finding(db,run_id,cse_id=case["cse_id"],asset_id=case["asset_id"],case_id=cid,family="missing_escalation",title="Critical case has no linked escalation",description="The completed critical case has no escalation in the complete synthetic escalation export.",priority="high",confidence="strong",observed={"linked_escalations":0},expected={"minimum":1,"policy_version":POLICY["version"],"searched_scope":"all escalation rows for this submission and CSE"},evidence=evidence+[{"table":"submissions","id":submission_id}],next_action="Inspect the case and request any authorised exception record.")
            if closed and case["severity"] in ("high","critical") and hours < POLICY["high_case_max_close_hours"] and not steps[cid]:
                add_finding(db,run_id,cse_id=case["cse_id"],asset_id=case["asset_id"],case_id=cid,family="premature_closure",title="Fast closure with no investigation step",description="Closure was rapid and no substantive investigation record is linked.",priority="high" if case["severity"]=="critical" else "medium",observed={"hours_to_close":round(hours,2),"investigation_steps":0},expected={"minimum_step":"investigate","demo_threshold_hours":POLICY["high_case_max_close_hours"]},evidence=evidence,alternative="An authorised automated closure or an investigation in another approved record may explain this.")
            if closed and len(trace)>=2:
                features.append([min(hours or 0,100),len(steps[cid]),len(escalations[cid]),len(missing),1 if case["severity"]=="critical" else 0,len(trace)])
                feature_cases.append(case)
        # Fit case-level model only on evidence features. A model-only outlier is provisional.
        try:
            import numpy as np
            from sklearn.ensemble import IsolationForest
            matrix=np.asarray(features,dtype=float)
            if len(matrix)>=40:
                model=IsolationForest(n_estimators=200,contamination=0.05,random_state=42).fit(matrix)
                scores=-model.score_samples(matrix)
                cutoff=float(np.quantile(scores,0.95))
                median=np.median(matrix,axis=0)
                for idx, score in enumerate(scores):
                    if score < cutoff: continue
                    case=feature_cases[idx]; cid=case["case_id"]
                    percentile=round(float(np.mean(scores<=score))*100,1)
                    sensitivity={}
                    for k,name in enumerate(("closure_hours","investigation_steps","escalation_count","missing_activities","critical_severity","event_count")):
                        changed=matrix[idx].copy(); changed[k]=median[k]
                        sensitivity[name]=round(float(score + model.score_samples(changed.reshape(1,-1))[0]),4)
                    add_finding(db,run_id,cse_id=case["cse_id"],asset_id=case["asset_id"],case_id=cid,family="case_shape_outlier",title="Unusual case shape for review",description="The case is unusual relative to this synthetic reference population; the score is not a probability of weak handling.",priority="low",confidence="provisional",queue="uncertain",observed={"anomaly_score":round(float(score),4),"reference_percentile":percentile,"features":dict(zip(sensitivity,features[idx]))},expected={"reference_cases":len(features),"threshold_score":round(cutoff,4)},evidence=[{"table":"cases","id":cid}],alternative="Efficient, well evidenced automation can also be unusual.",next_action="Review the feature evidence and case timeline before drawing a conclusion.",model={"engine":"IsolationForest","trees":200,"seed":42,"sensitivity":sensitivity,"version":"CASE-IF-1"})
                engines["case_anomaly"]="completed"
            else: engines["case_anomaly"]="not_assessable_too_few_cases"
        except ImportError: engines["case_anomaly"]="unavailable_dependency"
        # Daily expectation checks: explicit zero and absent records have different queues.
        daily=defaultdict(list)
        for r in allrows(db,"SELECT * FROM telemetry_daily"): daily[r["asset_id"]].append(r)
        maintenance=defaultdict(set)
        for r in allrows(db,"SELECT * FROM service_context"):
            a=datetime.fromisoformat(r["start_at"].replace("Z","+00:00")).date(); b=datetime.fromisoformat(r["end_at"].replace("Z","+00:00")).date()
            for d in range((b-a).days): maintenance[r["asset_id"]].add((a+timedelta(days=d)).isoformat())
        for asset_id, asset in assets.items():
            records=daily[asset_id]; eligible=[r for r in records if r["day"] not in maintenance[asset_id]]
            zero=[r for r in eligible if r["reporting_state"]=="explicit_zero" and r["heartbeat_count"]==0]
            healthy=sum(1 for r in eligible if r["heartbeat_count"]>0)
            if len(zero)>=3:
                add_finding(db,run_id,cse_id=asset["cse_id"],asset_id=asset_id,family="monitoring_gap",title="Expected monitoring has explicit zero days",description=f"{len(zero)} eligible days have explicit zero heartbeat records for this asset.",priority="high" if asset["criticality"]=="critical" else "medium",confidence="strong",observed={"zero_days":len(zero),"healthy_days":healthy,"unknown_days":0},expected={"eligible_days":len(eligible),"source":asset["source_id"],"policy_version":POLICY["version"]},evidence=[{"table":"telemetry_daily","id":r["record_id"],"ref":f"telemetry_daily.csv#{r['record_id']}"} for r in zero[-12:]]+[{"table":"monitoring_expectations","id":f"EXP-{asset_id}"}],alternative="A replacement monitoring source may exist outside the declared submission.",next_action="Verify source health, maintenance approval and any replacement feed.")
            if not records:
                add_finding(db,run_id,cse_id=asset["cse_id"],asset_id=asset_id,family="missing_coverage_data",title="Coverage evidence not assessable",description="No daily source summary was supplied for an expected asset.",priority="medium",confidence="insufficient",queue="data_attention",observed={"rows":0},expected={"source":asset["source_id"]},evidence=[{"table":"monitoring_expectations","id":f"EXP-{asset_id}"}],next_action="Request the missing source/day export.")
        # Exposure-normalised peer comparison, gated by distinct peer count.
        counts=Counter(a["cse_id"] for a in alerts); sectors={e["cse_id"]:e["sector"] for e in entities}
        exposure=Counter(a["cse_id"] for a in assets.values())
        for entity in entities:
            cse=entity["cse_id"]; peers=[x["cse_id"] for x in entities if x["sector"]==entity["sector"] and x["cse_id"]!=cse]
            if len(peers)<POLICY["minimum_peer_entities"]: continue
            values=[counts[p]/max(1,exposure[p]) for p in peers]
            med=statistics.median(values); mad=statistics.median(abs(v-med) for v in values)
            current=counts[cse]/max(1,exposure[cse])
            if mad>0 and current<med-3*mad:
                add_finding(db,run_id,cse_id=cse,family="peer_deviation",title="Lower alert rate than comparable peers",description="An exposure-normalised rate is below the peer median; context and coverage require review.",priority="low",confidence="provisional",queue="uncertain",observed={"alerts_per_asset":round(current,2)},expected={"peer_median":round(med,2),"peer_mad":round(mad,2),"peer_count":len(peers),"members":peers},evidence=[{"table":"entities","id":cse}],alternative="Different threat exposure, controls or reporting scope may explain the difference.")
        grouped=defaultdict(list)
        for alert in alerts:
            asset=assets.get(alert["asset_id"])
            if asset and alert["raised_at"]:
                grouped[(alert["cse_id"],alert["asset_id"],asset["source_id"],alert["source_user_id"])].append(alert)
        session_count=0
        for key,group in grouped.items():
            group.sort(key=lambda x:(x["raised_at"],x["alert_id"]))
            batches=[]; current=[]; last=None
            for alert in group:
                ts=datetime.fromisoformat(alert["raised_at"].replace("Z","+00:00"))
                if last and (ts-last).total_seconds()>POLICY["session_gap_minutes"]*60:
                    batches.append(current); current=[]
                current.append(alert); last=ts
            if current: batches.append(current)
            for batch in batches:
                session_count+=1
                db.execute("INSERT INTO event_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?)",(f"SES-{run_id}-{session_count:05d}",run_id,*key,batch[0]["raised_at"],batch[-1]["raised_at"],len(batch),j([x["alert_id"] for x in batch]),POLICY["session_gap_minutes"]))
        engines["sessionisation"]="completed"
        # Snapshot for independent analytical inspection. SQLite remains the mutable source.
        try:
            import duckdb
            snapshot=Path(db_path).with_suffix(".duckdb")
            con=duckdb.connect(str(snapshot)); con.execute("CREATE OR REPLACE TABLE assessment_summary (cse_id VARCHAR, finding_count INTEGER, high_count INTEGER)")
            summary_rows=allrows(db,"SELECT cse_id,count(*) finding_count,sum(CASE WHEN priority='high' THEN 1 ELSE 0 END) high_count FROM findings WHERE run_id=? GROUP BY cse_id",(run_id,))
            con.executemany("INSERT INTO assessment_summary VALUES (?,?,?)",[(r["cse_id"],r["finding_count"],r["high_count"]) for r in summary_rows]); con.close()
            engines["duckdb_snapshot"]="completed"
        except ImportError: engines["duckdb_snapshot"]="unavailable_dependency"
        counts_by_family=allrows(db,"SELECT family,count(*) n FROM findings WHERE run_id=? GROUP BY family",(run_id,))
        summary={"entities":len(entities),"assets":len(assets),"alerts":len(alerts),"cases":len(cases),"findings":sum(x["n"] for x in counts_by_family),"families":{x["family"]:x["n"] for x in counts_by_family},"synthetic":True}
        status="completed" if all(v not in ("unavailable_dependency",) for v in engines.values()) else "completed_degraded"
        db.execute("UPDATE runs SET finished_at=?,status=?,engine_json=?,summary_json=? WHERE run_id=?",(stamp(),status,j(engines),j(summary),run_id)); db.commit()
        return {"run_id":run_id,"status":status,"summary":summary,"engines":engines}
    except Exception:
        db.execute("UPDATE runs SET finished_at=?,status='failed',engine_json=? WHERE run_id=?",(stamp(),j(engines),run_id)); db.commit(); raise
    finally: db.close()

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--db",default="data/prahari.sqlite"); p.add_argument("--submission",default="SUB-DEMO-1"); a=p.parse_args()
    print(json.dumps(run(a.db,a.submission),indent=2))
