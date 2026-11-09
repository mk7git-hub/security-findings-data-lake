"""Kinesis Data Firehose transform: flatten GuardDuty and Security Hub events into one schema.

Firehose then converts each JSON record to Parquet using the Glue table schema and writes
it to S3 partitioned by source and date. Unknown events are dropped, malformed ones are
marked ProcessingFailed so Firehose routes them to the error prefix.
"""
import base64
import json

SEVERITY = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _gd_label(score):
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def from_guardduty(evt):
    d = evt["detail"]
    res = d.get("resource", {})
    rtype = res.get("resourceType", "")
    rid = (res.get("instanceDetails", {}).get("instanceId")
           or (res.get("accessKeyDetails") or {}).get("accessKeyId")
           or ((res.get("s3BucketDetails") or [{}])[0]).get("name") or "")
    label = _gd_label(float(d.get("severity", 0)))
    return [{
        "source": "guardduty", "finding_id": d["id"], "account_id": d["accountId"], "region": d["region"],
        "type": d["type"], "title": d.get("title", ""), "severity_label": label, "severity_rank": SEVERITY[label],
        "resource_type": rtype, "resource_id": rid, "control_id": "", "compliance_status": "",
        "workflow_status": "", "first_seen": d.get("createdAt", ""), "last_seen": d.get("updatedAt", ""),
    }]


def from_securityhub(evt):
    rows = []
    for f in evt["detail"].get("findings", []):
        res = (f.get("Resources") or [{}])[0]
        label = (f.get("Severity") or {}).get("Label", "INFORMATIONAL")
        rows.append({
            "source": "securityhub", "finding_id": f["Id"], "account_id": f["AwsAccountId"], "region": f.get("Region", ""),
            "type": ";".join(f.get("Types", [])), "title": f.get("Title", ""), "severity_label": label,
            "severity_rank": SEVERITY.get(label, 0), "resource_type": res.get("Type", ""), "resource_id": res.get("Id", ""),
            "control_id": (f.get("Compliance") or {}).get("SecurityControlId", ""),
            "compliance_status": (f.get("Compliance") or {}).get("Status", ""),
            "workflow_status": (f.get("Workflow") or {}).get("Status", ""),
            "first_seen": f.get("FirstObservedAt", f.get("CreatedAt", "")), "last_seen": f.get("UpdatedAt", ""),
        })
    return rows


def flatten(evt):
    src = evt.get("source")
    if src == "aws.guardduty":
        return from_guardduty(evt)
    if src == "aws.securityhub":
        return from_securityhub(evt)
    return []


def handler(event, context=None):
    out = []
    for rec in event["records"]:
        try:
            rows = flatten(json.loads(base64.b64decode(rec["data"])))
        except (KeyError, ValueError, TypeError):
            out.append({"recordId": rec["recordId"], "result": "ProcessingFailed", "data": rec["data"]})
            continue
        if not rows:
            out.append({"recordId": rec["recordId"], "result": "Dropped", "data": rec["data"]})
            continue
        if len(rows) > 1:
            # Parquet conversion needs one JSON object per record. Security Hub sends one finding per
            # EventBridge event, so this is rare; the raw event goes to the error prefix, never lost.
            out.append({"recordId": rec["recordId"], "result": "ProcessingFailed", "data": rec["data"]})
            continue
        body = json.dumps(rows[0]) + "\n"
        out.append({"recordId": rec["recordId"], "result": "Ok", "data": base64.b64encode(body.encode()).decode(),
                    "metadata": {"partitionKeys": {"source": rows[0]["source"]}}})
    return {"records": out}
