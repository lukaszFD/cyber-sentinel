-- Updated view for analysis queue
-- Uses FQDN naming and links to source_ip for better context
CREATE OR REPLACE VIEW cyber_intelligence.v_pending_analysis AS
SELECT
    dq.id AS dns_query_id,
    dq.source_ip,
    dq.domain AS fqdn,
    GROUP_CONCAT(DISTINCT dq.response_ip ORDER BY dq.response_ip SEPARATOR ', ') AS observable_ip,
    MIN(dq.timestamp) AS first_seen
FROM cyber_intelligence.dns_queries dq
         LEFT JOIN cyber_intelligence.threat_indicators ti ON dq.id = ti.dns_query_id
WHERE ti.id IS NULL
  AND dq.response_ip REGEXP '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
GROUP BY dq.id, dq.source_ip, dq.domain;