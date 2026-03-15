CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_threat_explorer AS
SELECT
    ne.timestamp,
    dq.domain AS fqdn,
    ne.source_ip,
    ne.request_url,
    (SELECT GROUP_CONCAT(sp.name SEPARATOR ', ') 
     FROM cyber_intelligence.threat_indicator_details tid
     JOIN cyber_intelligence.dic_source_providers sp ON tid.source_id = sp.id
     WHERE tid.indicator_id = ti.id) AS providers,
    tl.description AS threat_label,
    ar.threat_score
FROM cyber_intelligence.network_events ne
JOIN cyber_intelligence.dns_queries dq ON ne.dns_query_id = dq.id
JOIN cyber_intelligence.threat_indicators ti ON ne.threat_indicator_id = ti.id
JOIN cyber_intelligence.ai_analysis_results ar ON ti.analysis_result_id = ar.id
JOIN cyber_intelligence.dic_threat_levels tl ON ar.threat_score = tl.score
WHERE ar.threat_score > 5;