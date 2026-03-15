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