-- Dictionary for indicator types
-- Stores types like FQDN, IP, or file HASH
CREATE TABLE IF NOT EXISTS dic_indicator_types (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(20) NOT NULL UNIQUE
);

INSERT IGNORE INTO dic_indicator_types (name) VALUES
('FQDN'),
('IP'),
('HASH');