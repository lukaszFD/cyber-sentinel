CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_daily_trends AS
SELECT
    DATE(last_scan) AS scan_date,
    UNIX_TIMESTAMP(DATE(MAX(last_scan))) AS time_sec,
    COUNT(id) AS total_scans_per_day,
    SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) AS total_positives_per_day,
    MAX(threat_score) AS max_threat_score_that_day
FROM
    cyber_intelligence.v_latest_threat_reports
GROUP BY
    scan_date;