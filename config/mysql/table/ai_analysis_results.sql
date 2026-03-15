CREATE TABLE IF NOT EXISTS cyber_intelligence.ai_analysis_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    threat_score INT NOT NULL,
    verdict_summary_en TEXT,
    analysis_pl TEXT,
    CONSTRAINT fk_threat_level_results FOREIGN KEY (threat_score) REFERENCES cyber_intelligence.dic_threat_levels(score)
) ENGINE=InnoDB;