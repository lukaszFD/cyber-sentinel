CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_threat_alerts AS
SELECT
    ti.id AS indicator_id,
    dq.timestamp AS detection_time,
    dq.domain AS fqdn,
    dq.record_type,                -- Z Twojej tabeli dns_queries
    dq.response_ip AS observable_ip,
    tl.score AS threat_score,      -- Z Twojej tabeli dic_threat_levels
    tl.description AS threat_label, -- Opis poziomu (np. High Risk)
    tl.is_malicious_flag,
    ar.verdict_en,                 -- POPRAWIONE: Pobierane z ai_analysis_results
    ar.analysis_pl                 -- POPRAWIONE: Pobierane z ai_analysis_results
FROM
    cyber_intelligence.threat_indicators ti
JOIN
    cyber_intelligence.dns_queries dq ON ti.dns_query_id = dq.id
JOIN
    cyber_intelligence.ai_analysis_results ar ON ti.analysis_result_id = ar.id
JOIN
    cyber_intelligence.dic_threat_levels tl ON ar.threat_score = tl.score
ORDER BY
    dq.timestamp DESC;