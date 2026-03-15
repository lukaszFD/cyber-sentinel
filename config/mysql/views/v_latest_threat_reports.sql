CREATE OR REPLACE VIEW cyber_intelligence.v_latest_threat_reports AS
SELECT
    ti.id,
    ti.dns_query_id,
    ti.type_id,
    ti.analysis_result_id,
    ti.last_scan,
    ar.threat_score,
    ar.verdict_summary_en,
    ar.analysis_pl
FROM cyber_intelligence.threat_indicators ti
JOIN cyber_intelligence.ai_analysis_results ar ON ti.analysis_result_id = ar.id
INNER JOIN (
    SELECT dns_query_id, MAX(last_scan) as max_scan
    FROM cyber_intelligence.threat_indicators
    GROUP BY dns_query_id
) latest ON ti.dns_query_id = latest.dns_query_id AND ti.last_scan = latest.max_scan;