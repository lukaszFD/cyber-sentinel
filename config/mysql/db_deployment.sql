-- ============================================
-- Cyber Intelligence Database Deployment
-- Version: 3.0
-- Changes vs v2.0:
--   - Threat scale changed from 1-10 to 1-5 (see migration_threat_scale_v3)
--   - Composite primary keys for tables that will be partitioned
--     (dns_queries, network_events, threat_indicators) — required by MySQL
--   - threat_indicators UNIQUE KEY extended with last_scan to allow
--     multiple scans of the same (dns_query, analysis_result) pair
--   - Grafana views updated to use is_malicious_flag instead of score > 5
-- ============================================

-- Database creation
CREATE DATABASE IF NOT EXISTS cyber_intelligence
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cyber_intelligence;

-- ============================================
-- SECTION 1: USER MANAGEMENT
-- ============================================

CREATE USER IF NOT EXISTS '{{ mysql_user }}'@'%' IDENTIFIED BY '{{ vault_mysql_password }}';
GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_intelligence.* TO '{{ mysql_user }}'@'%';
GRANT CREATE VIEW ON cyber_intelligence.* TO '{{ mysql_user }}'@'%';
FLUSH PRIVILEGES;

-- ============================================
-- SECTION 2: DICTIONARY TABLES
-- ============================================

-- Indicator types (FQDN, IP, HASH)
CREATE TABLE IF NOT EXISTS dic_indicator_types (
                                                   id INT AUTO_INCREMENT PRIMARY KEY,
                                                   name VARCHAR(20) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO dic_indicator_types (name) VALUES
('FQDN'),
('IP'),
('HASH');

-- Threat intelligence source providers
CREATE TABLE IF NOT EXISTS dic_source_providers (
                                                    id INT AUTO_INCREMENT PRIMARY KEY,
                                                    name VARCHAR(50) NOT NULL UNIQUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name),
    INDEX idx_active (is_active)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO dic_source_providers (name) VALUES
('VirusTotal'),
('Abuse_ThreatFox'),
('Abuse_URLhaus'),
('urlscan.io');

-- Threat severity levels (1-5 scale, dynamically loaded by AI agent)
CREATE TABLE IF NOT EXISTS dic_threat_levels (
                                                 score INT PRIMARY KEY,
                                                 description VARCHAR(100) NOT NULL,
    is_malicious_flag BOOLEAN DEFAULT FALSE,
    action_recommended VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO dic_threat_levels (score, description, is_malicious_flag, action_recommended) VALUES
(1, 'Clean / Trusted infrastructure',           FALSE, 'Allow'),
(2, 'Low Risk / Monitor',                       FALSE, 'Monitor'),
(3, 'Suspicious - manual review needed',        FALSE, 'Review'),
(4, 'Malicious - confirmed threat',             TRUE,  'Block'),
(5, 'Critical - active threat, immediate alert', TRUE,  'Block + Alert');

-- ============================================
-- SECTION 3: CORE DATA TABLES
-- ============================================
-- IMPORTANT: Tables that will be partitioned (dns_queries, network_events,
-- threat_indicators) use COMPOSITE PRIMARY KEYS that include the partitioning
-- column. This is mandatory in MySQL — see ER 1503.
-- ============================================

-- Passive DNS query log (partitioned by timestamp)
CREATE TABLE IF NOT EXISTS dns_queries (
                                           id INT AUTO_INCREMENT,
                                           timestamp DATETIME NOT NULL,
                                           query_type VARCHAR(10) NOT NULL,
    record_type VARCHAR(10),
    domain VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    response_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, timestamp),
    INDEX idx_id (id),
    INDEX idx_domain (domain),
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_response_ip (response_ip),
    INDEX idx_domain_timestamp (domain, timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- AI/ML analysis results (NOT partitioned — relatively small, FK target)
CREATE TABLE IF NOT EXISTS ai_analysis_results (
                                                   id INT AUTO_INCREMENT PRIMARY KEY,
                                                   threat_score INT NOT NULL,
                                                   threat_label VARCHAR(50),
    verdict_summary_en TEXT,
    analysis_pl TEXT,
    confidence_score DECIMAL(5,2) DEFAULT NULL,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_threat_level_results
    FOREIGN KEY (threat_score)
    REFERENCES dic_threat_levels(score)
    ON DELETE RESTRICT
    ON UPDATE CASCADE,
    INDEX idx_threat_score (threat_score),
    INDEX idx_analyzed_at (analyzed_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Threat indicators — partitioned by last_scan
-- NOTE: PARTITIONED TABLES CANNOT HAVE FOREIGN KEYS in MySQL.
-- We enforce relational integrity at the application layer (n8n workflow).
-- The composite PK and UNIQUE KEY include last_scan to satisfy partitioning rules.
CREATE TABLE IF NOT EXISTS threat_indicators (
                                                 id INT AUTO_INCREMENT,
                                                 dns_query_id INT NOT NULL,
                                                 type_id INT NOT NULL,
                                                 analysis_result_id INT NOT NULL,
                                                 last_scan DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                                 scan_count INT DEFAULT 1,
                                                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                 PRIMARY KEY (id, last_scan),
    UNIQUE KEY uk_dns_analysis_scan (dns_query_id, analysis_result_id, last_scan),
    INDEX idx_id (id),
    INDEX idx_dns_query (dns_query_id),
    INDEX idx_last_scan (last_scan),
    INDEX idx_type (type_id),
    INDEX idx_analysis_result (analysis_result_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Detailed threat intelligence from external sources (NOT partitioned)
-- FK to threat_indicators removed because partitioned tables cannot be FK targets.
CREATE TABLE IF NOT EXISTS threat_indicator_details (
                                                        id INT AUTO_INCREMENT PRIMARY KEY,
                                                        indicator_id INT NOT NULL,
                                                        source_id INT NOT NULL,
                                                        mongo_ref_id VARCHAR(50),
    raw_response_hash VARCHAR(64),
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_source
    FOREIGN KEY (source_id)
    REFERENCES dic_source_providers(id)
    ON DELETE RESTRICT
    ON UPDATE CASCADE,
    INDEX idx_indicator (indicator_id),
    INDEX idx_source (source_id),
    INDEX idx_mongo_ref (mongo_ref_id),
    UNIQUE KEY uk_indicator_source (indicator_id, source_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Network security events (partitioned by timestamp)
-- FKs to dns_queries and threat_indicators removed because both are partitioned.
CREATE TABLE IF NOT EXISTS network_events (
                                              id INT AUTO_INCREMENT,
                                              timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                              dns_query_id INT NULL,
                                              threat_indicator_id INT NULL,

    -- Network details
                                              source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    dest_port INT,
    protocol VARCHAR(10),
    application_protocol VARCHAR(20),

    -- HTTP/Request details
    request_url TEXT,
    user_agent TEXT,
    http_method VARCHAR(10),

    -- Security metadata
    event_type VARCHAR(50),
    severity INT,
    signature_name VARCHAR(255),
    action_taken VARCHAR(20),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id, timestamp),
    INDEX idx_id (id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_severity (severity),
    INDEX idx_event_type (event_type),
    INDEX idx_dns_query (dns_query_id),
    INDEX idx_threat_indicator (threat_indicator_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================
-- SECTION 4: VIEWS FOR ANALYSIS & REPORTING
-- ============================================

-- Pending analysis queue (DNS queries without threat intel)
CREATE OR REPLACE VIEW v_pending_analysis AS
SELECT
    dq.id AS dns_query_id,
    dq.source_ip,
    dq.domain AS fqdn,
    GROUP_CONCAT(DISTINCT dq.response_ip ORDER BY dq.response_ip SEPARATOR ', ') AS observable_ip,
    MIN(dq.timestamp) AS first_seen,
    COUNT(DISTINCT dq.id) AS query_count
FROM dns_queries dq
         LEFT JOIN threat_indicators ti ON dq.id = ti.dns_query_id
WHERE ti.id IS NULL
  AND dq.response_ip REGEXP '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
GROUP BY dq.id, dq.source_ip, dq.domain;

-- Latest threat reports (most recent scan per DNS query)
CREATE OR REPLACE VIEW v_latest_threat_reports AS
SELECT
    ti.id,
    ti.dns_query_id,
    ti.type_id,
    ti.analysis_result_id,
    ti.last_scan,
    ti.scan_count,
    ar.threat_score,
    ar.threat_label,
    ar.verdict_summary_en,
    ar.analysis_pl,
    ar.confidence_score
FROM threat_indicators ti
         JOIN ai_analysis_results ar ON ti.analysis_result_id = ar.id
         INNER JOIN (
    SELECT dns_query_id, MAX(last_scan) AS max_scan
    FROM threat_indicators
    GROUP BY dns_query_id
) latest ON ti.dns_query_id = latest.dns_query_id AND ti.last_scan = latest.max_scan;

-- ============================================
-- SECTION 5: GRAFANA VIEWS (using new 1-5 scale via is_malicious_flag)
-- ============================================

CREATE OR REPLACE VIEW v_grafana_malicious_stats AS
SELECT
    COUNT(vlt.id) AS total_scans,
    SUM(CASE WHEN tl.is_malicious_flag = TRUE THEN 1 ELSE 0 END) AS total_malicious_scans,
    ROUND((SUM(CASE WHEN tl.is_malicious_flag = TRUE THEN 1 ELSE 0 END) / COUNT(vlt.id)) * 100, 2) AS malicious_percentage,
    MAX(vlt.last_scan) AS last_scan,
    MIN(vlt.last_scan) AS first_scan
FROM v_latest_threat_reports vlt
         JOIN dic_threat_levels tl ON vlt.threat_score = tl.score;

CREATE OR REPLACE VIEW v_grafana_daily_trends AS
SELECT
    DATE(vlt.last_scan) AS scan_date,
    UNIX_TIMESTAMP(DATE(MAX(vlt.last_scan))) AS time_sec,
    COUNT(vlt.id) AS total_scans_per_day,
    SUM(CASE WHEN tl.is_malicious_flag = TRUE THEN 1 ELSE 0 END) AS total_positives_per_day,
    SUM(CASE WHEN tl.is_malicious_flag = FALSE THEN 1 ELSE 0 END) AS total_clean_per_day,
    MAX(vlt.threat_score) AS max_threat_score_that_day,
    AVG(vlt.threat_score) AS avg_threat_score
FROM v_latest_threat_reports vlt
    JOIN dic_threat_levels tl ON vlt.threat_score = tl.score
GROUP BY scan_date
ORDER BY scan_date DESC;

CREATE OR REPLACE VIEW v_grafana_dns_hourly_traffic AS
SELECT
    DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') AS hour_group,
    UNIX_TIMESTAMP(DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00')) AS time_sec,
    COUNT(id) AS total_queries,
    COUNT(DISTINCT domain) AS unique_domains,
    COUNT(DISTINCT source_ip) AS unique_sources,
    MAX(timestamp) AS latest_query
FROM dns_queries
GROUP BY hour_group, time_sec
ORDER BY hour_group DESC;

CREATE OR REPLACE VIEW v_grafana_threat_explorer AS
SELECT
    ne.timestamp,
    dq.domain AS fqdn,
    ne.source_ip,
    ne.dest_ip,
    ne.request_url,
    ne.event_type,
    (SELECT GROUP_CONCAT(sp.name SEPARATOR ', ')
     FROM threat_indicator_details tid
              JOIN dic_source_providers sp ON tid.source_id = sp.id
     WHERE tid.indicator_id = ti.id) AS providers,
    tl.description AS threat_label,
    tl.action_recommended,
    ar.threat_score,
    ne.action_taken
FROM network_events ne
         JOIN dns_queries dq ON ne.dns_query_id = dq.id
         JOIN threat_indicators ti ON ne.threat_indicator_id = ti.id
         JOIN ai_analysis_results ar ON ti.analysis_result_id = ar.id
         JOIN dic_threat_levels tl ON ar.threat_score = tl.score
WHERE tl.is_malicious_flag = TRUE
ORDER BY ne.timestamp DESC;

CREATE OR REPLACE VIEW v_grafana_threat_alerts AS
SELECT
    ti.id AS indicator_id,
    dq.timestamp AS detection_time,
    dq.domain AS fqdn,
    dq.record_type,
    dq.source_ip,
    dq.response_ip AS observable_ip,
    ar.threat_score,
    tl.description AS threat_label,
    tl.is_malicious_flag,
    tl.action_recommended,
    ar.verdict_summary_en AS verdict_en,
    ar.analysis_pl,
    ar.confidence_score,
    ti.scan_count,
    ti.last_scan
FROM threat_indicators ti
         JOIN dns_queries dq ON ti.dns_query_id = dq.id
         JOIN ai_analysis_results ar ON ti.analysis_result_id = ar.id
         JOIN dic_threat_levels tl ON ar.threat_score = tl.score
WHERE tl.is_malicious_flag = TRUE
ORDER BY dq.timestamp DESC, ar.threat_score DESC;

-- Helper view for AI agent — fetches threat scale at every invocation
CREATE OR REPLACE VIEW v_threat_scale_for_agent AS
SELECT
    score,
    description,
    is_malicious_flag,
    action_recommended,
    CONCAT(score, ' | ', description, ' (Action: ', action_recommended, ')') AS formatted_line
FROM dic_threat_levels
ORDER BY score ASC;

-- ============================================
-- DEPLOYMENT COMPLETE
-- Database: cyber_intelligence
-- Tables: 8 core tables (3 ready for partitioning)
-- Views: 7 reporting views
-- Threat scale: 1-5 (dynamic, loaded from dic_threat_levels)
-- Next step: run db_partitioning_retention_v3.sql
-- ============================================