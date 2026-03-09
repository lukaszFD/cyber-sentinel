-- View for high-level security event exploration
CREATE OR REPLACE VIEW v_grafana_threat_explorer AS
SELECT
    ne.timestamp,
    dq.domain AS fqdn,
    ne.source_ip,
    ne.request_url,
    sp.name AS provider,
    tl.description AS threat_label,
    ti.threat_score
FROM network_events ne
JOIN dns_queries dq ON ne.dns_query_id = dq.id
JOIN threat_indicators ti ON ne.threat_indicator_id = ti.id
JOIN dic_source_providers sp ON ti.source_id = sp.id
JOIN dic_threat_levels tl ON ti.threat_score = tl.score
WHERE ti.threat_score > 5; -- Only suspicious or malicious