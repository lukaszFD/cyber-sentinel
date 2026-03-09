-- Updated view for analysis queue
-- Uses FQDN naming and links to source_ip for better context
CREATE OR REPLACE VIEW v_pending_analysis AS
SELECT DISTINCT
    dq.id AS dns_query_id,
    dq.source_ip,
    dq.domain AS fqdn,
    dq.response_ip AS observable_ip,
    dq.timestamp AS first_seen
FROM dns_queries dq
LEFT JOIN threat_indicators ti ON dq.id = ti.dns_query_id
WHERE ti.id IS NULL
  AND dq.response_ip REGEXP '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$';
