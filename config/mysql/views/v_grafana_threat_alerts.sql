CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_threat_alerts AS
SELECT
    ti.id AS indicator_id,
    dq.timestamp AS detection_time,
    dq.domain AS fqdn,
    dq.record_type,
    dq.response_ip AS observable_ip,
    ar.threat_score,
    tl.description AS threat_label,
    tl.is_malicious_flag,
    ar.verdict_summary_en AS verdict_en,
    ar.analysis_pl
FROM
    cyber_intelligence.threat_indicators ti
        JOIN
    cyber_intelligence.dns_queries dq ON ti.dns_query_id = dq.id
        JOIN
    cyber_intelligence.ai_analysis_results ar ON ti.analysis_result_id = ar.id
        JOIN
    cyber_intelligence.dic_threat_levels tl ON ar.threat_score = tl.score
WHERE
    ar.threat_score > 0
ORDER BY
    dq.timestamp DESC;