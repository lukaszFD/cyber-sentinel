-- Database creation for Cyber Intelligence System
CREATE DATABASE IF NOT EXISTS cyber_intelligence;
USE cyber_intelligence;

-- User configuration for application access
-- These variables will be replaced by Ansible during deployment
CREATE USER IF NOT EXISTS '{{ mysql_app_user }}'@'%' IDENTIFIED BY '{{ mysql_password }}';
GRANT ALL PRIVILEGES ON cyber_intelligence.* TO '{{ mysql_app_user }}'@'%';
FLUSH PRIVILEGES;

-- 1. Main table for standardized threat data (Link to MongoDB)
-- This table stores the "verdict" and a reference to the raw data in Mongo
CREATE TABLE IF NOT EXISTS threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    observable VARCHAR(255) NOT NULL,        -- Domain, IP, or SHA256
    type ENUM('DOMAIN', 'IP', 'HASH') NOT NULL,
    source_provider VARCHAR(50) NOT NULL,    -- e.g., 'virustotal', 'abuseipdb'
    is_malicious BOOLEAN DEFAULT FALSE,
    threat_score INT DEFAULT 0,              -- Normalized 0-100
    verdict_summary TEXT,                    -- Short summary for Grafana
    mongo_ref_id VARCHAR(50),                -- Object ID from MongoDB (threat_data_lake)
    last_scan DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY idx_unique_indicator (observable, source_provider),
    INDEX idx_observable (observable),
    INDEX idx_verdict (is_malicious)
) ENGINE=InnoDB;

-- 2. Passive DNS History table
-- Populated by your Python dns_log_processor.py
CREATE TABLE IF NOT EXISTS dns_queries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    response_ip VARCHAR(45),
    INDEX idx_domain (domain),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Analytics View: Domains waiting for AI/CTI analysis
-- Shows domains from DNS logs that are not yet in the threat_indicators table
CREATE OR REPLACE VIEW v_pending_analysis AS
SELECT DISTINCT
    dq.domain,
    dq.timestamp as first_seen
FROM dns_queries dq
LEFT JOIN threat_indicators ti ON dq.domain = ti.observable
WHERE ti.id IS NULL
AND dq.domain NOT REGEXP '^[0-9.]+$'; -- Exclude direct IP queries

-- 4. Analytics View: High Risk Indicators (for Grafana Dashboard)
CREATE OR REPLACE VIEW v_security_alerts AS
SELECT
    observable,
    type,
    source_provider,
    threat_score,
    verdict_summary,
    mongo_ref_id,
    last_scan
FROM threat_indicators
WHERE is_malicious = TRUE OR threat_score > 70;

-- 5. Maintenance Procedure: Data Retention
DELIMITER //
CREATE PROCEDURE clean_old_intelligence(IN days_to_keep INT)
BEGIN
    DELETE FROM dns_queries WHERE timestamp < NOW() - INTERVAL days_to_keep DAY;
    -- We usually keep threat_indicators longer for historical correlation
END //
DELIMITER ;