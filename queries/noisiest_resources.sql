-- Resources with the most open findings: where to fix first
SELECT resource_type, resource_id, count(*) AS open_findings, max(severity_label) AS worst
FROM findings
WHERE coalesce(workflow_status, '') NOT IN ('RESOLVED', 'SUPPRESSED')
GROUP BY resource_type, resource_id
ORDER BY open_findings DESC
LIMIT 25;
