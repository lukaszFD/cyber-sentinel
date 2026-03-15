CREATE TABLE IF NOT EXISTS cyber_intelligence.threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dns_query_id INT NOT NULL,
    type_id INT NOT NULL,
    analysis_result_id INT NOT NULL,
    last_scan DATETIME DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dns_query FOREIGN KEY (dns_query_id) REFERENCES cyber_intelligence.dns_queries(id),
    CONSTRAINT fk_indicator_type FOREIGN KEY (type_id) REFERENCES cyber_intelligence.dic_indicator_types(id),
    CONSTRAINT fk_analysis_result FOREIGN KEY (analysis_result_id) REFERENCES cyber_intelligence.ai_analysis_results(id)
) ENGINE=InnoDB;