-- HIGH and CRITICAL findings from both services in the last day
SELECT source, severity_label, type, resource_type, resource_id, last_seen
FROM findings
WHERE severity_rank >= 3 AND dt >= cast(current_date - interval '1' day AS varchar)
ORDER BY severity_rank DESC, last_seen DESC;
