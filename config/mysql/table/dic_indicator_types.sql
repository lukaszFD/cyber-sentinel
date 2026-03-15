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