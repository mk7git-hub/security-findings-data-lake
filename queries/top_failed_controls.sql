-- Which Security Hub controls fail most, and on how many resources
SELECT control_id, any_value(title) AS title, count(DISTINCT resource_id) AS resources
FROM findings
WHERE source = 'securityhub' AND compliance_status = 'FAILED' AND dt >= cast(current_date - interval '7' day AS varchar)
GROUP BY control_id
ORDER BY resources DESC
LIMIT 20;
