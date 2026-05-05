-- ============================================
-- DATA RETENTION STRATEGY
-- Cyber Intelligence System v3.0
-- ============================================
-- Strategy: Monthly partitioning with 6-month retention
-- Tables: dns_queries, network_events, threat_indicators
-- Automation: MySQL Event Scheduler
--
-- PREREQUISITES:
--   1. Run db_deployment_v3.sql FIRST (composite PKs required)
--   2. Tables must be empty OR data must fall within initial partition range
--   3. partition_maintenance_log must be created BEFORE procedures use it
-- ============================================

USE cyber_intelligence;

-- ============================================
-- PART 1: MAINTENANCE LOG TABLE (must be first — procedures depend on it)
-- ============================================
CREATE TABLE IF NOT EXISTS partition_maintenance_log (
                                                         id INT AUTO_INCREMENT PRIMARY KEY,
                                                         table_name VARCHAR(100) NOT NULL,
    partition_name VARCHAR(50) NOT NULL,
    action VARCHAR(20) NOT NULL,
    error_message TEXT,
    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_executed_at (executed_at),
    INDEX idx_table_name (table_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- PART 2: ENABLE PARTITIONING ON TABLES
-- ============================================
-- Initial partitions cover current month + 3 future months.
-- Adjust the dates below to match the deployment date.
-- ============================================

-- dns_queries — partitioned by timestamp (DATETIME)
ALTER TABLE dns_queries
    PARTITION BY RANGE (TO_DAYS(timestamp)) (
    PARTITION p202604 VALUES LESS THAN (TO_DAYS('2026-05-01')),
    PARTITION p202605 VALUES LESS THAN (TO_DAYS('2026-06-01')),
    PARTITION p202606 VALUES LESS THAN (TO_DAYS('2026-07-01')),
    PARTITION p202607 VALUES LESS THAN (TO_DAYS('2026-08-01')),
    PARTITION p_future VALUES LESS THAN MAXVALUE
    );

-- network_events — partitioned by timestamp (DATETIME)
ALTER TABLE network_events
    PARTITION BY RANGE (TO_DAYS(timestamp)) (
    PARTITION p202604 VALUES LESS THAN (TO_DAYS('2026-05-01')),
    PARTITION p202605 VALUES LESS THAN (TO_DAYS('2026-06-01')),
    PARTITION p202606 VALUES LESS THAN (TO_DAYS('2026-07-01')),
    PARTITION p202607 VALUES LESS THAN (TO_DAYS('2026-08-01')),
    PARTITION p_future VALUES LESS THAN MAXVALUE
    );

-- threat_indicators — partitioned by last_scan (DATETIME)
ALTER TABLE threat_indicators
    PARTITION BY RANGE (TO_DAYS(last_scan)) (
    PARTITION p202604 VALUES LESS THAN (TO_DAYS('2026-05-01')),
    PARTITION p202605 VALUES LESS THAN (TO_DAYS('2026-06-01')),
    PARTITION p202606 VALUES LESS THAN (TO_DAYS('2026-07-01')),
    PARTITION p202607 VALUES LESS THAN (TO_DAYS('2026-08-01')),
    PARTITION p_future VALUES LESS THAN MAXVALUE
    );

-- ============================================
-- PART 3: STORED PROCEDURES FOR MAINTENANCE
-- ============================================

DROP PROCEDURE IF EXISTS sp_drop_old_partitions;
DROP PROCEDURE IF EXISTS sp_add_future_partitions;

DELIMITER $$

-- ----------------------------------------------------------------
-- Procedure: drop ALL partitions older than 6 months
-- Iterates over INFORMATION_SCHEMA.PARTITIONS instead of guessing
-- a single partition name (fixes the bug in v1 which only handled
-- exactly one partition per run).
-- ----------------------------------------------------------------
CREATE PROCEDURE sp_drop_old_partitions()
BEGIN
    DECLARE v_done INT DEFAULT 0;
    DECLARE v_table_name VARCHAR(100);
    DECLARE v_partition_name VARCHAR(50);
    DECLARE v_cutoff_yyyymm VARCHAR(6);
    DECLARE v_partition_yyyymm VARCHAR(6);

    -- Cursor: all monthly partitions on our 3 partitioned tables, except p_future
    DECLARE cur CURSOR FOR
SELECT TABLE_NAME, PARTITION_NAME
FROM INFORMATION_SCHEMA.PARTITIONS
WHERE TABLE_SCHEMA = 'cyber_intelligence'
  AND TABLE_NAME IN ('dns_queries', 'network_events', 'threat_indicators')
  AND PARTITION_NAME IS NOT NULL
  AND PARTITION_NAME != 'p_future'
          AND PARTITION_NAME REGEXP '^p[0-9]{6}$';

DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;

    -- Cutoff = 6 months ago, formatted as YYYYMM (matches partition naming)
    SET v_cutoff_yyyymm = DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 6 MONTH), '%Y%m');

OPEN cur;

drop_loop: LOOP
        FETCH cur INTO v_table_name, v_partition_name;
        IF v_done = 1 THEN
            LEAVE drop_loop;
END IF;

        -- Extract YYYYMM from partition name (e.g. 'p202510' -> '202510')
        SET v_partition_yyyymm = SUBSTRING(v_partition_name, 2);

        -- Only drop if partition is older than the cutoff
        IF v_partition_yyyymm < v_cutoff_yyyymm THEN
            SET @sql = CONCAT('ALTER TABLE ', v_table_name,
                              ' DROP PARTITION ', v_partition_name);

            -- Best-effort execution: log success or failure but don't abort cursor
BEGIN
                DECLARE EXIT HANDLER FOR SQLEXCEPTION
BEGIN
INSERT INTO partition_maintenance_log
(table_name, partition_name, action, error_message)
VALUES (v_table_name, v_partition_name, 'DROP_FAILED',
        'SQLEXCEPTION during DROP PARTITION');
END;

PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

INSERT INTO partition_maintenance_log
(table_name, partition_name, action)
VALUES (v_table_name, v_partition_name, 'DROP');
END;
END IF;
END LOOP drop_loop;

CLOSE cur;
END$$

-- ----------------------------------------------------------------
-- Procedure: add future partitions for next 3 months
-- Loops month-by-month and reorganises p_future for each.
-- Uses information_schema check to skip months that already exist.
-- ----------------------------------------------------------------
CREATE PROCEDURE sp_add_future_partitions()
BEGIN
    DECLARE v_target_month DATE;
    DECLARE v_partition_name VARCHAR(50);
    DECLARE v_next_month_first DATE;
    DECLARE i INT DEFAULT 1;

    WHILE i <= 3 DO
        -- v_target_month = first day of (current month + i months)
        SET v_target_month = DATE_ADD(DATE_FORMAT(CURDATE(), '%Y-%m-01'),
                                       INTERVAL i MONTH);
        SET v_partition_name = CONCAT('p', DATE_FORMAT(v_target_month, '%Y%m'));
        -- The partition for month M holds rows where timestamp < first day of M+1
        SET v_next_month_first = DATE_ADD(v_target_month, INTERVAL 1 MONTH);

        -- dns_queries
        IF NOT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = 'cyber_intelligence'
              AND TABLE_NAME = 'dns_queries'
              AND PARTITION_NAME = v_partition_name
        ) THEN
            SET @sql = CONCAT(
                'ALTER TABLE dns_queries REORGANIZE PARTITION p_future INTO (',
                'PARTITION ', v_partition_name,
                ' VALUES LESS THAN (TO_DAYS(''',
                DATE_FORMAT(v_next_month_first, '%Y-%m-%d'), ''')),',
                'PARTITION p_future VALUES LESS THAN MAXVALUE)'
            );
BEGIN
                DECLARE EXIT HANDLER FOR SQLEXCEPTION
                    INSERT INTO partition_maintenance_log
                        (table_name, partition_name, action, error_message)
                    VALUES ('dns_queries', v_partition_name, 'ADD_FAILED',
                            'SQLEXCEPTION during REORGANIZE PARTITION');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
INSERT INTO partition_maintenance_log
(table_name, partition_name, action)
VALUES ('dns_queries', v_partition_name, 'ADD');
END;
END IF;

        -- network_events
        IF NOT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = 'cyber_intelligence'
              AND TABLE_NAME = 'network_events'
              AND PARTITION_NAME = v_partition_name
        ) THEN
            SET @sql = CONCAT(
                'ALTER TABLE network_events REORGANIZE PARTITION p_future INTO (',
                'PARTITION ', v_partition_name,
                ' VALUES LESS THAN (TO_DAYS(''',
                DATE_FORMAT(v_next_month_first, '%Y-%m-%d'), ''')),',
                'PARTITION p_future VALUES LESS THAN MAXVALUE)'
            );
BEGIN
                DECLARE EXIT HANDLER FOR SQLEXCEPTION
                    INSERT INTO partition_maintenance_log
                        (table_name, partition_name, action, error_message)
                    VALUES ('network_events', v_partition_name, 'ADD_FAILED',
                            'SQLEXCEPTION during REORGANIZE PARTITION');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
INSERT INTO partition_maintenance_log
(table_name, partition_name, action)
VALUES ('network_events', v_partition_name, 'ADD');
END;
END IF;

        -- threat_indicators
        IF NOT EXISTS (
            SELECT 1 FROM INFORMATION_SCHEMA.PARTITIONS
            WHERE TABLE_SCHEMA = 'cyber_intelligence'
              AND TABLE_NAME = 'threat_indicators'
              AND PARTITION_NAME = v_partition_name
        ) THEN
            SET @sql = CONCAT(
                'ALTER TABLE threat_indicators REORGANIZE PARTITION p_future INTO (',
                'PARTITION ', v_partition_name,
                ' VALUES LESS THAN (TO_DAYS(''',
                DATE_FORMAT(v_next_month_first, '%Y-%m-%d'), ''')),',
                'PARTITION p_future VALUES LESS THAN MAXVALUE)'
            );
BEGIN
                DECLARE EXIT HANDLER FOR SQLEXCEPTION
                    INSERT INTO partition_maintenance_log
                        (table_name, partition_name, action, error_message)
                    VALUES ('threat_indicators', v_partition_name, 'ADD_FAILED',
                            'SQLEXCEPTION during REORGANIZE PARTITION');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
INSERT INTO partition_maintenance_log
(table_name, partition_name, action)
VALUES ('threat_indicators', v_partition_name, 'ADD');
END;
END IF;

        SET i = i + 1;
END WHILE;
END$$

DELIMITER ;

-- ============================================
-- PART 4: AUTOMATED EVENTS (MySQL Event Scheduler)
-- ============================================

SET GLOBAL event_scheduler = ON;

DROP EVENT IF EXISTS evt_drop_old_partitions;
DROP EVENT IF EXISTS evt_add_future_partitions;

-- Drop old partitions (1st day of each month at 2 AM)
CREATE EVENT evt_drop_old_partitions
ON SCHEDULE EVERY 1 MONTH
STARTS (TIMESTAMP(DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 1 MONTH), '%Y-%m-01'), '02:00:00'))
DO
    CALL sp_drop_old_partitions();

-- Add future partitions (1st day of each month at 3 AM)
CREATE EVENT evt_add_future_partitions
ON SCHEDULE EVERY 1 MONTH
STARTS (TIMESTAMP(DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 1 MONTH), '%Y-%m-01'), '03:00:00'))
DO
    CALL sp_add_future_partitions();

-- ============================================
-- PART 5: UTILITY VIEW
-- ============================================

CREATE OR REPLACE VIEW v_partition_info AS
SELECT
    TABLE_NAME,
    PARTITION_NAME,
    PARTITION_METHOD,
    PARTITION_EXPRESSION,
    PARTITION_DESCRIPTION,
    TABLE_ROWS,
    ROUND(DATA_LENGTH / 1024 / 1024, 2) AS data_mb,
    ROUND(INDEX_LENGTH / 1024 / 1024, 2) AS index_mb,
    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS total_mb,
    CREATE_TIME,
    UPDATE_TIME
FROM INFORMATION_SCHEMA.PARTITIONS
WHERE TABLE_SCHEMA = 'cyber_intelligence'
  AND PARTITION_NAME IS NOT NULL
ORDER BY TABLE_NAME, PARTITION_NAME;

-- ============================================
-- VERIFICATION QUERIES (run manually after deployment)
-- ============================================
-- SELECT * FROM v_partition_info;
-- SHOW EVENTS FROM cyber_intelligence;
-- SELECT * FROM partition_maintenance_log ORDER BY executed_at DESC LIMIT 20;
-- SELECT @@global.event_scheduler;  -- should return ON
--
-- Manual trigger for testing:
-- CALL sp_add_future_partitions();
-- CALL sp_drop_old_partitions();
-- ============================================