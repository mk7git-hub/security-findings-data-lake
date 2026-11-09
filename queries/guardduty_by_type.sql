-- GuardDuty finding types trend by day
SELECT dt, type, count(*) AS findings
FROM findings
WHERE source = 'guardduty'
GROUP BY dt, type
ORDER BY dt DESC, findings DESC;
