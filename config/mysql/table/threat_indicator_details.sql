CREATE TABLE IF NOT EXISTS cyber_intelligence.threat_indicator_details (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_id INT NOT NULL,
    source_id INT NOT NULL,
    mongo_ref_id VARCHAR(50),  -- Reference to raw data in MongoDB
    FOREIGN KEY (indicator_id) REFERENCES cyber_intelligence.threat_indicators(id) ON DELETE CASCADE,
    FOREIGN KEY (source_id) REFERENCES cyber_intelligence.dic_source_providers(id)
);

CREATE INDEX idx_mongo_ref ON cyber_intelligence.threat_indicator_details(mongo_ref_id);