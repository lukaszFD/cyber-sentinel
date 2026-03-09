CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_dns_hourly_traffic AS
SELECT
    -- 1. Main grouping column
    DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') AS hour_group,
    -- 2. This must also be in GROUP BY to satisfy 'only_full_group_by'
    UNIX_TIMESTAMP(DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00')) AS time_sec,
    -- 3. Aggregated values
    COUNT(id) AS total_queries,
    MAX(timestamp) AS raw_time
FROM
    cyber_intelligence.dns_queries
GROUP BY
    hour_group, 
    time_sec;