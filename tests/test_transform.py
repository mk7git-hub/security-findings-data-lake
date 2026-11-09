import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
import transform as t  # noqa: E402

GD = {"source": "aws.guardduty", "detail-type": "GuardDuty Finding", "detail": {
    "id": "gd-1", "accountId": "111122223333", "region": "us-east-1", "type": "UnauthorizedAccess:EC2/SSHBruteForce",
    "title": "SSH brute force", "severity": 8.0, "createdAt": "2026-11-06T10:00:00Z", "updatedAt": "2026-11-06T10:05:00Z",
    "resource": {"resourceType": "Instance", "instanceDetails": {"instanceId": "i-0abc"}}}}
SH = {"source": "aws.securityhub", "detail-type": "Security Hub Findings - Imported", "detail": {"findings": [
    {"Id": "sh-1", "AwsAccountId": "111122223333", "Region": "us-east-1", "Types": ["Software and Configuration Checks"],
     "Title": "S3 general purpose buckets should block public access", "Severity": {"Label": "HIGH"},
     "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::demo"}], "Compliance": {"SecurityControlId": "S3.8", "Status": "FAILED"},
     "Workflow": {"Status": "NEW"}, "FirstObservedAt": "2026-11-06T09:00:00Z", "UpdatedAt": "2026-11-06T09:30:00Z"},
    {"Id": "sh-2", "AwsAccountId": "111122223333", "Region": "us-east-1", "Types": [], "Title": "x",
     "Severity": {"Label": "LOW"}, "Resources": [{"Type": "AwsAccount", "Id": "AWS::::Account:111122223333"}]}]}}


def rec(obj, rid="1"):
    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
    return {"recordId": rid, "data": base64.b64encode(raw).decode()}


def rows_of(r):
    return [json.loads(x) for x in base64.b64decode(r["data"]).decode().splitlines()]


def test_guardduty_flattened_with_severity_label():
    r = t.handler({"records": [rec(GD)]})["records"][0]
    assert r["result"] == "Ok" and r["metadata"]["partitionKeys"]["source"] == "guardduty"
    row = rows_of(r)[0]
    assert row["severity_label"] == "HIGH" and row["resource_id"] == "i-0abc"


SH1 = {**SH, "detail": {"findings": SH["detail"]["findings"][:1]}}


def test_securityhub_finding_flattened():
    rows = rows_of(t.handler({"records": [rec(SH1)]})["records"][0])
    assert len(rows) == 1 and rows[0]["control_id"] == "S3.8" and rows[0]["severity_rank"] == 3


def test_multi_finding_event_kept_in_error_prefix_not_lost():
    r = t.handler({"records": [rec(SH)]})["records"][0]
    assert r["result"] == "ProcessingFailed" and r["data"] == rec(SH)["data"]


def test_schema_is_identical_across_sources():
    a = rows_of(t.handler({"records": [rec(GD)]})["records"][0])[0]
    b = rows_of(t.handler({"records": [rec(SH1)]})["records"][0])[0]
    assert set(a) == set(b)


def test_unknown_source_dropped_and_garbage_failed():
    out = t.handler({"records": [rec({"source": "aws.ec2"}, "a"), rec(b"not json", "b")]})["records"]
    assert [o["result"] for o in out] == ["Dropped", "ProcessingFailed"]


def test_guardduty_severity_bands():
    assert [t._gd_label(s) for s in (1, 4, 7, 9.5)] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
