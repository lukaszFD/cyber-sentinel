CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_malicious_stats AS
SELECT
    COUNT(id) AS total_scans,
    SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) AS total_malicious_scans,
    (SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) / COUNT(id)) * 100 AS malicious_percentage,
    MAX(last_scan) AS last_scan
FROM
    cyber_intelligence.v_latest_threat_reports;