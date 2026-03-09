-- Database creation for Cyber Intelligence System
CREATE DATABASE IF NOT EXISTS cyber_intelligence;
USE cyber_intelligence;

-- User configuration for application access
-- These variables will be replaced by Ansible during deployment
CREATE USER IF NOT EXISTS '{{ mysql_user }}'@'%' IDENTIFIED BY '{{ vault_mysql_password }}';
GRANT ALL PRIVILEGES ON cyber_intelligence.* TO '{{ mysql_user }}'@'%';
FLUSH PRIVILEGES;

-- Dictionary for indicator types
-- Stores types like FQDN, IP, or file HASH
CREATE TABLE IF NOT EXISTS cyber_intelligence.dic_indicator_types (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(20) NOT NULL UNIQUE
);

INSERT IGNORE INTO cyber_intelligence.dic_indicator_types (name) VALUES
('FQDN'),
('IP'),
('HASH');

-- Dictionary for CTI (Cyber Threat Intelligence) providers
-- Stores names of external services used for scanning
CREATE TABLE IF NOT EXISTS cyber_intelligence.dic_source_providers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

INSERT IGNORE INTO cyber_intelligence.dic_source_providers (name) VALUES
('VirusTotal'),
('Abuse_ThreatFox'),
('Abuse_URLhaus'),
('urlscan.io');

-- Dictionary for threat levels (Scoring Policy)
-- Defines risk levels from 1 to 10 with descriptive actions
CREATE TABLE IF NOT EXISTS cyber_intelligence.dic_threat_levels (
    score INT PRIMARY KEY,
    description VARCHAR(100) NOT NULL,
    is_malicious_flag BOOLEAN DEFAULT FALSE
);

INSERT IGNORE INTO cyber_intelligence.dic_threat_levels (score, description, is_malicious_flag) VALUES
(1, 'Safe / Clean', FALSE),
(2, 'Low Risk', FALSE),
(3, 'Informational / CDN', FALSE),
(4, 'Unverified / New', FALSE),
(5, 'Suspicious - review needed', FALSE),
(6, 'Likely Malicious - investigation required', TRUE),
(7, 'Malicious - known threat', TRUE),
(8, 'High Risk - immediate attention', TRUE),
(9, 'Confirmed Malware - to be blocked', TRUE),
(10, 'Critical Threat - active attack', TRUE);

-- Passive DNS History table
-- Populated by your Python dns_log_processor.py
CREATE TABLE IF NOT EXISTS cyber_intelligence.dns_queries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    response_ip VARCHAR(45),
    INDEX idx_domain (domain),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Main table for threat indicators
-- Linked to dns_queries and dictionaries via Foreign Keys
CREATE TABLE IF NOT EXISTS cyber_intelligence.threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dns_query_id INT NOT NULL, -- FK to dns_queries table
    type_id INT NOT NULL,      -- FK to dic_indicator_types
    source_id INT NOT NULL,    -- FK to dic_source_providers
    threat_score INT NOT NULL, -- FK to dic_threat_levels
    verdict_summary TEXT,      -- Summary of the scan result
    mongo_ref_id VARCHAR(50),  -- Reference to raw data in MongoDB
    last_scan DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dns_query FOREIGN KEY (dns_query_id) REFERENCES cyber_intelligence.dns_queries(id),
    CONSTRAINT fk_indicator_type FOREIGN KEY (type_id) REFERENCES cyber_intelligence.dic_indicator_types(id),
    CONSTRAINT fk_source_provider FOREIGN KEY (source_id) REFERENCES cyber_intelligence.dic_source_providers(id),
    CONSTRAINT fk_threat_level FOREIGN KEY (threat_score) REFERENCES cyber_intelligence.dic_threat_levels(score)
) ENGINE=InnoDB;

-- Universal table for network events (IDS/IPS, Scapy, Sniffers)
-- Stores specific actions like clicked URLs, downloaded files, or triggered alerts
CREATE TABLE IF NOT EXISTS cyber_intelligence.network_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dns_query_id INT NULL,          -- FK to DNS query context (optional)
    threat_indicator_id INT NULL,   -- FK to an existing threat report (optional)
    source_ip VARCHAR(45) NOT NULL, -- Client IP
    dest_ip VARCHAR(45) NOT NULL,   -- Destination IP
    dest_port INT,
    protocol VARCHAR(10),           -- TCP, UDP, ICMP
    application_protocol VARCHAR(20), -- HTTP, TLS, DNS, FTP

    -- URL / Path details
    request_url TEXT,               -- Full URL or URI path clicked/requested
    user_agent TEXT,                -- Browser/Client identification

    -- Security Metadata
    event_type VARCHAR(50),         -- 'alert', 'flow', 'http_request', 'scapy_intercept'
    severity INT,                   -- Normalized severity (e.g., 1-5)
    signature_name VARCHAR(255),    -- If IDS: name of the rule triggered (Suricata)
    action_taken VARCHAR(20),       -- 'allowed', 'blocked', 'logged'

    CONSTRAINT fk_event_dns_query FOREIGN KEY (dns_query_id) REFERENCES cyber_intelligence.dns_queries(id),
    CONSTRAINT fk_event_threat FOREIGN KEY (threat_indicator_id) REFERENCES cyber_intelligence.threat_indicators(id)
) ENGINE=InnoDB;

-- Updated view for analysis queue
-- Uses FQDN naming and links to source_ip for better context
CREATE OR REPLACE VIEW cyber_intelligence.v_pending_analysis AS
SELECT DISTINCT
    dq.id AS dns_query_id,
    dq.source_ip,
    dq.domain AS fqdn,
    dq.response_ip AS observable_ip,
    dq.timestamp AS first_seen
FROM cyber_intelligence.dns_queries dq
LEFT JOIN cyber_intelligence.threat_indicators ti ON dq.id = ti.dns_query_id
WHERE ti.id IS NULL
  AND dq.response_ip REGEXP '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$';

-- View to get only the most recent scan per DNS query
CREATE OR REPLACE VIEW cyber_intelligence.v_latest_threat_reports AS
SELECT ti.*
FROM cyber_intelligence.threat_indicators ti
INNER JOIN (
    -- Group by dns_query_id and source_id to get latest scan per provider
    SELECT dns_query_id, source_id, MAX(last_scan) as max_scan
    FROM cyber_intelligence.threat_indicators
    GROUP BY dns_query_id, source_id
) latest ON ti.dns_query_id = latest.dns_query_id
         AND ti.source_id = latest.source_id
         AND ti.last_scan = latest.max_scan;

-- View for global malicious scan statistics
CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_malicious_stats AS
SELECT
    COUNT(id) AS total_scans,
    SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) AS total_malicious_scans,
    (SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) / COUNT(id)) * 100 AS malicious_percentage,
    MAX(last_scan) AS last_scan
FROM
    cyber_intelligence.v_latest_threat_reports;

-- View for daily trends of scans and threats
CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_daily_trends AS
SELECT
    DATE(last_scan) AS scan_date,
    UNIX_TIMESTAMP(DATE(MAX(last_scan))) AS time_sec,
    COUNT(id) AS total_scans_per_day,
    SUM(CASE WHEN threat_score > 5 THEN 1 ELSE 0 END) AS total_positives_per_day,
    MAX(threat_score) AS max_threat_score_that_day
FROM
    cyber_intelligence.v_latest_threat_reports
GROUP BY
    scan_date;

-- View for aggregating DNS traffic intensity per hour
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

-- View for high-level security event exploration
CREATE OR REPLACE VIEW cyber_intelligence.v_grafana_threat_explorer AS
SELECT
    ne.timestamp,
    dq.domain AS fqdn,
    ne.source_ip,
    ne.request_url,
    sp.name AS provider,
    tl.description AS threat_label,
    ti.threat_score
FROM cyber_intelligence.network_events ne
JOIN cyber_intelligence.dns_queries dq ON ne.dns_query_id = dq.id
JOIN cyber_intelligence.threat_indicators ti ON ne.threat_indicator_id = ti.id
JOIN cyber_intelligence.dic_source_providers sp ON ti.source_id = sp.id
JOIN cyber_intelligence.dic_threat_levels tl ON ti.threat_score = tl.score
WHERE ti.threat_score > 5; -- Only suspicious or malicious