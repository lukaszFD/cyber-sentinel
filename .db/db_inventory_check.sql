-- ============================================================
-- Cyber Sentinel — Postgres inventory / diagnostic queries
-- ============================================================
-- Run these in pgAdmin's Query Tool, section by section (or all at
-- once — pgAdmin shows results per-statement in a tabbed grid when
-- you run the whole script with F5).
-- ============================================================

-- ------------------------------------------------------------
-- 1. All tables (excluding partitions — those show separately below)
-- ------------------------------------------------------------
SELECT
    c.relname AS table_name,
    CASE c.relkind WHEN 'p' THEN 'partitioned table' ELSE 'table' END AS kind,
    pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'cyber_sentinel'
  AND c.relkind IN ('r', 'p')           -- 'r' = ordinary table, 'p' = partitioned parent
  AND c.relispartition = false          -- excludes individual partitions
ORDER BY table_name;

-- ------------------------------------------------------------
-- 2. All views
-- ------------------------------------------------------------
SELECT
    table_name AS view_name
FROM information_schema.views
WHERE table_schema = 'cyber_sentinel'
ORDER BY view_name;

-- ------------------------------------------------------------
-- 3. Row counts per table (approximate, from stats — fast, no full scan)
-- ------------------------------------------------------------
SELECT
    relname AS table_name,
    n_live_tup AS approx_row_count
FROM pg_stat_user_tables
WHERE schemaname = 'cyber_sentinel'
ORDER BY relname;

-- ------------------------------------------------------------
-- 4. Partitions per partitioned table (dns_queries, network_events, threat_indicators)
-- ------------------------------------------------------------
SELECT * FROM cyber_sentinel.v_partition_info;

-- ------------------------------------------------------------
-- 5. Extensions installed
-- ------------------------------------------------------------
SELECT extname AS extension, extversion AS version
FROM pg_extension
ORDER BY extname;

-- ------------------------------------------------------------
-- 6. pg_cron scheduled jobs (partition maintenance automation)
-- ------------------------------------------------------------
SELECT jobid, jobname, schedule, command, active
FROM cron.job
ORDER BY jobid;

-- Last 20 runs of those jobs (useful once the 1st-of-month schedule has fired)
SELECT jobid, runid, job_pid, status, return_message, start_time, end_time
FROM cron.job_run_details
ORDER BY start_time DESC
    LIMIT 20;

-- ------------------------------------------------------------
-- 7. Roles (users) — should show 'postgres' + your app role
-- ------------------------------------------------------------
SELECT rolname, rolsuper, rolcreatedb, rolcanlogin
FROM pg_roles
ORDER BY rolname;

-- ------------------------------------------------------------
-- 8. Foreign key constraints — confirms the real FKs Postgres allowed
--    that MySQL never could (threat_indicators -> ai_analysis_results,
--    threat_indicators -> dic_indicator_types, threat_indicator_details
--    -> threat_data_raw)
-- ------------------------------------------------------------
SELECT
    tc.table_name,
    kcu.column_name,
    ccu.table_name AS references_table,
    ccu.column_name AS references_column,
    tc.constraint_name
FROM information_schema.table_constraints tc
         JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
         JOIN information_schema.constraint_column_usage ccu
              ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema
WHERE tc.constraint_type = 'FOREIGN KEY'
  AND tc.table_schema = 'cyber_sentinel'
ORDER BY tc.table_name;

-- ------------------------------------------------------------
-- 9. Quick peek at data in every core table (uncomment what you need —
--    left commented since most are empty right after deployment)
-- ------------------------------------------------------------
-- SELECT * FROM cyber_sentinel.dic_indicator_types;
-- SELECT * FROM cyber_sentinel.dic_source_providers;
-- SELECT * FROM cyber_sentinel.dic_threat_levels;
-- SELECT * FROM cyber_sentinel.dns_queries LIMIT 100;
-- SELECT * FROM cyber_sentinel.network_events LIMIT 100;
-- SELECT * FROM cyber_sentinel.threat_indicators LIMIT 100;
-- SELECT * FROM cyber_sentinel.threat_indicator_details LIMIT 100;
-- SELECT * FROM cyber_sentinel.ai_analysis_results LIMIT 100;
-- SELECT * FROM cyber_sentinel.threat_data_raw LIMIT 100;
-- SELECT * FROM cyber_sentinel.partition_maintenance_log ORDER BY executed_at DESC LIMIT 50;

-- ------------------------------------------------------------
-- 10. Grafana views — confirm they return data once dns_queries has rows
-- ------------------------------------------------------------
-- SELECT * FROM cyber_sentinel.v_pending_analysis LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_latest_threat_reports LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_grafana_malicious_stats;
-- SELECT * FROM cyber_sentinel.v_grafana_daily_trends LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_grafana_dns_hourly_traffic LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_grafana_threat_explorer LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_grafana_threat_alerts LIMIT 50;
-- SELECT * FROM cyber_sentinel.v_threat_scale_for_agent;