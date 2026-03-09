-- Main table for threat indicators
-- Linked to dns_queries and dictionaries via Foreign Keys
CREATE TABLE IF NOT EXISTS threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dns_query_id INT NOT NULL, -- FK to dns_queries table
    type_id INT NOT NULL,      -- FK to dic_indicator_types
    source_id INT NOT NULL,    -- FK to dic_source_providers
    threat_score INT NOT NULL, -- FK to dic_threat_levels
    verdict_summary TEXT,      -- Summary of the scan result
    mongo_ref_id VARCHAR(50),  -- Reference to raw data in MongoDB
    last_scan DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dns_query FOREIGN KEY (dns_query_id) REFERENCES dns_queries(id),
    CONSTRAINT fk_indicator_type FOREIGN KEY (type_id) REFERENCES dic_indicator_types(id),
    CONSTRAINT fk_source_provider FOREIGN KEY (source_id) REFERENCES dic_source_providers(id),
    CONSTRAINT fk_threat_level FOREIGN KEY (threat_score) REFERENCES dic_threat_levels(score)
) ENGINE=InnoDB;
