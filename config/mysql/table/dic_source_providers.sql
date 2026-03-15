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
('urlscan.io'),
('Cyber Sentinel AI');