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

    CONSTRAINT fk_event_dns_query FOREIGN KEY (dns_query_id) REFERENCES dns_queries(id),
    CONSTRAINT fk_event_threat FOREIGN KEY (threat_indicator_id) REFERENCES threat_indicators(id)
) ENGINE=InnoDB;

-- Indexing for high-performance correlation queries
CREATE INDEX idx_network_event_ips ON cyber_intelligence.network_events(source_ip, dest_ip);
CREATE INDEX idx_network_event_time ON cyber_intelligence.network_events(timestamp);