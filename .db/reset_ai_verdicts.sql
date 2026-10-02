-- ============================================
-- Reset AI verdicts for selected DNS queries (test re-scan)
-- After COMMIT the domain + IP pair reappears in
-- cyber_sentinel_ai.v_pending_observables and n8n will analyse it again.
-- Run the WHOLE script at once (temp tables live only in this transaction).
-- ============================================

BEGIN;

-- 1. INPUT: dns_queries.id values to reset
CREATE TEMP TABLE tmp_target_dns ON COMMIT DROP AS
SELECT unnest(ARRAY[103]) AS dns_query_id;

-- 2. Domain + IP pairs behind those DNS queries (the view groups by this pair)
CREATE TEMP TABLE tmp_pairs ON COMMIT DROP AS
SELECT DISTINCT dq.domain AS fqdn, dq.response_ip AS observable_ip
FROM cyber_sentinel.dns_queries dq
         JOIN tmp_target_dns t ON t.dns_query_id = dq.id;

-- 3. Every verdict for those pairs: AI audit rows + indicators linked
--    through any DNS query of the same pair (catches rows without audit)
CREATE TEMP TABLE tmp_results ON COMMIT DROP AS
SELECT va.analysis_result_id AS id
FROM cyber_sentinel_ai.verdict_audit va
         JOIN tmp_pairs p ON p.fqdn = va.fqdn AND p.observable_ip = va.observable_ip
UNION
SELECT ti.analysis_result_id
FROM cyber_sentinel.threat_indicators ti
         JOIN cyber_sentinel.dns_queries dq ON dq.id = ti.dns_query_id
         JOIN tmp_pairs p ON p.fqdn = dq.domain AND p.observable_ip = dq.response_ip;

CREATE TEMP TABLE tmp_indicators ON COMMIT DROP AS
SELECT ti.id
FROM cyber_sentinel.threat_indicators ti
WHERE ti.analysis_result_id IN (SELECT id FROM tmp_results);

CREATE TEMP TABLE tmp_raw ON COMMIT DROP AS
SELECT DISTINCT tid.raw_data_id AS id
FROM cyber_sentinel.threat_indicator_details tid
WHERE tid.indicator_id IN (SELECT id FROM tmp_indicators)
  AND tid.raw_data_id IS NOT NULL;

-- 4. Delete (child -> parent order)
-- network_events.threat_indicator_id has no FK (partitioned target) - detach manually
UPDATE cyber_sentinel.network_events
SET threat_indicator_id = NULL
WHERE threat_indicator_id IN (SELECT id FROM tmp_indicators);

DELETE FROM cyber_sentinel.threat_indicator_details
WHERE indicator_id IN (SELECT id FROM tmp_indicators);

DELETE FROM cyber_sentinel.threat_indicators
WHERE analysis_result_id IN (SELECT id FROM tmp_results);

-- Would cascade from ai_analysis_results anyway - explicit for readability
DELETE FROM cyber_sentinel_ai.verdict_vectors
WHERE analysis_result_id IN (SELECT id FROM tmp_results);

DELETE FROM cyber_sentinel_ai.verdict_audit
WHERE analysis_result_id IN (SELECT id FROM tmp_results);

DELETE FROM cyber_sentinel.ai_analysis_results
WHERE id IN (SELECT id FROM tmp_results);

-- Raw payloads are created per scan; delete only if nothing else points to them
DELETE FROM cyber_sentinel.threat_data_raw r
WHERE r.id IN (SELECT id FROM tmp_raw)
  AND NOT EXISTS (SELECT 1 FROM cyber_sentinel.threat_indicator_details d WHERE d.raw_data_id = r.id);

-- 5. Verification (sees the uncommitted deletes of this transaction)
SELECT
    p.fqdn,
    p.observable_ip,
    (SELECT count(*) FROM tmp_results)    AS verdicts_deleted,
    (SELECT count(*) FROM tmp_indicators) AS indicators_deleted,
    (SELECT count(*) FROM tmp_raw)        AS raw_payloads_deleted,
    EXISTS (SELECT 1 FROM cyber_sentinel_ai.v_pending_observables v
            WHERE v.fqdn = p.fqdn AND v.observable_ip = p.observable_ip) AS back_in_queue,
    cyber_sentinel_ai.is_allowlisted(p.fqdn) AS allowlisted
FROM tmp_pairs p;

COMMIT;   -- change to ROLLBACK; for a dry run