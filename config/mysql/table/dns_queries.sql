-- Passive DNS History table
-- Populated by your Python dns_log_processor.py
CREATE TABLE IF NOT EXISTS cyber_intelligence.dns_queries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    record_type VARCHAR(10),
    domain VARCHAR(255) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    response_ip VARCHAR(45),
    INDEX idx_domain (domain),
    INDEX idx_timestamp (timestamp)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
