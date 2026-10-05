-- ============================================
-- Cyber Sentinel — AI config editor (web UI) — POSTGRES
-- Version: 1.0
-- ============================================
-- Runs AFTER db_ai_pipeline.sql, as the `postgres` superuser, connected to
-- `cyber_intelligence`. Rendered by Ansible (template module, playbook
-- 04_5_ai_config_editor.yml). Fully idempotent — safe to re-run.
--
-- PURPOSE:
--   A dedicated, least-privilege login role for the AI config web UI
--   (ai-config-ui container). It is NOT the superuser and NOT the n8n app
--   role ({{ postgres_user }}): it can only read/change the data that
--   drives the n8n AI pipeline, nothing else.
--
-- WHAT THE ROLE CAN DO (everything else is denied by default):
--   cyber_sentinel_ai.ai_settings              SELECT, UPDATE(value) only
--   cyber_sentinel_ai.prompt_templates         SELECT, INSERT, UPDATE, DELETE
--   cyber_sentinel_ai.trusted_infrastructure   SELECT, INSERT, UPDATE, DELETE
--   cyber_sentinel_ai.domain_allowlist_exclusions SELECT, INSERT, UPDATE, DELETE
--   cyber_sentinel_ai.domain_allowlist         SELECT only (Tranco rows are
--                                              owned by the weekly sync)
--   cyber_sentinel_ai.v_manual_allowlist       SELECT, INSERT, UPDATE, DELETE
--                                              (manual rows only — see below)
--   cyber_sentinel_ai.domain_allowlist_sync_log SELECT
--   cyber_sentinel_ai.config_change_log        SELECT (written by trigger)
--   cyber_sentinel.dic_threat_levels           SELECT, UPDATE(description,
--                                              action_recommended,
--                                              is_malicious_flag) — wording feeds
--                                              [[THREAT_SCALE]] in the prompt,
--                                              the flag drives Grafana
--   cyber_sentinel.v_threat_scale_for_agent    SELECT (prompt preview)
--
--   ai_settings has no INSERT/DELETE on purpose: every key is read by
--   cyber_sentinel_ai.setting(), which RAISES on a missing key — deleting
--   a row from the UI would stop the workflow and v_pending_observables.
--   New keys come from db_ai_pipeline.sql (code change = deploy, not UI).
--
--   No INSERT/DELETE on dic_threat_levels: the 1-5 range is hard-wired in
--   compute_threat_score(), the prompt and ai_analysis_results' FK — adding
--   or removing a level is a code change, not a data change.
--   is_malicious_flag IS editable, guarded by trg_threat_levels_malicious
--   (malicious levels must be a contiguous top range, e.g. 4-5 or 3-5).
--
-- OBJECTS ADDED (additive only — no existing object is altered or dropped):
--   v_manual_allowlist          auto-updatable view: source = 'manual' rows,
--                               WITH CHECK OPTION, so the UI can never touch
--                               or create Tranco rows
--   config_change_log           who changed what, old/new row as JSONB
--   trg_config_change_log()     SECURITY DEFINER audit trigger function
--   trg_ai_settings_touch()     keeps ai_settings.updated_at current
--   trg_prompt_guard()          active prompt cannot be edited or deleted
--   trg_prompt_one_active()     deferred check: exactly one active prompt
--                               at COMMIT (activation = 2 UPDATEs in 1 tx)
--   trg_threat_levels_malicious() deferred check: malicious flags form a
--                               contiguous top range and at least the
--                               highest level is malicious
--
-- AUDIT ACTOR: the web UI runs
--     SELECT set_config('cyber_sentinel_ai.actor', '<ui user>', true)
-- at the start of every transaction. Changes made any other way (psql,
-- n8n) are logged with the database session_user instead.
-- Rows with source = 'tranco' in domain_allowlist are NOT logged — the
-- weekly sync touches thousands of them and has its own sync_log.
-- ============================================

-- ============================================
-- SECTION 1: ROLE
-- ============================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{{ ai_config_db_user }}') THEN
        CREATE ROLE "{{ ai_config_db_user }}" LOGIN PASSWORD '{{ vault_ai_config_db_password }}'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
            CONNECTION LIMIT 10;
    ELSE
        ALTER ROLE "{{ ai_config_db_user }}" WITH LOGIN PASSWORD '{{ vault_ai_config_db_password }}'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
            CONNECTION LIMIT 10;
    END IF;
END
$$;

-- Fail fast instead of hanging the UI on a lock held by a long n8n run.
ALTER ROLE "{{ ai_config_db_user }}" SET statement_timeout = '15s';
ALTER ROLE "{{ ai_config_db_user }}" SET lock_timeout = '5s';
ALTER ROLE "{{ ai_config_db_user }}" SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE "{{ ai_config_db_user }}" SET search_path = cyber_sentinel_ai, cyber_sentinel;

GRANT CONNECT ON DATABASE cyber_intelligence TO "{{ ai_config_db_user }}";
-- USAGE only — never CREATE: the role must not be able to add objects.
GRANT USAGE ON SCHEMA cyber_sentinel_ai TO "{{ ai_config_db_user }}";
GRANT USAGE ON SCHEMA cyber_sentinel    TO "{{ ai_config_db_user }}";

-- ============================================
-- SECTION 2: AUDIT LOG
-- ============================================

CREATE TABLE IF NOT EXISTS cyber_sentinel_ai.config_change_log (
    id          BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    changed_at  TIMESTAMP NOT NULL DEFAULT LOCALTIMESTAMP,
    actor       TEXT NOT NULL,
    db_user     TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    operation   VARCHAR(10) NOT NULL,
    row_key     TEXT,
    old_data    JSONB,
    new_data    JSONB
);
CREATE INDEX IF NOT EXISTS idx_config_change_log_changed
    ON cyber_sentinel_ai.config_change_log (changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_config_change_log_table
    ON cyber_sentinel_ai.config_change_log (table_name, changed_at DESC);

-- Append-only, enforced in the database rather than by grants alone:
-- db_ai_pipeline.sql re-runs `GRANT ... ON ALL TABLES IN SCHEMA
-- cyber_sentinel_ai` to the n8n role on every deployment, which would
-- silently hand it INSERT/UPDATE/DELETE on this log again. This guard
-- holds regardless of grants: rows can only be INSERTed from inside the
-- audit trigger (trigger depth > 1), and only a superuser session can
-- UPDATE, DELETE or TRUNCATE (manual pruning stays possible).
CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_config_change_log_guard()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = session_user) THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    IF TG_OP = 'INSERT' AND pg_trigger_depth() > 1 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'cyber_sentinel_ai.config_change_log is append-only (% denied for %)', TG_OP, session_user;
END
$$;

DROP TRIGGER IF EXISTS trg_config_change_log_guard ON cyber_sentinel_ai.config_change_log;
CREATE TRIGGER trg_config_change_log_guard
    BEFORE INSERT OR UPDATE OR DELETE ON cyber_sentinel_ai.config_change_log
    FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_config_change_log_guard();

DROP TRIGGER IF EXISTS trg_config_change_log_guard_truncate ON cyber_sentinel_ai.config_change_log;
CREATE TRIGGER trg_config_change_log_guard_truncate
    BEFORE TRUNCATE ON cyber_sentinel_ai.config_change_log
    FOR EACH STATEMENT EXECUTE FUNCTION cyber_sentinel_ai.trg_config_change_log_guard();

-- TG_ARGV[0] = primary-key column name, used for row_key.
-- SECURITY DEFINER (owner: postgres) so the editor role never needs
-- INSERT on the log itself — it cannot forge or delete audit rows.
CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_config_change_log()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_old JSONB := CASE WHEN TG_OP IN ('UPDATE', 'DELETE') THEN to_jsonb(OLD) END;
    v_new JSONB := CASE WHEN TG_OP IN ('INSERT', 'UPDATE') THEN to_jsonb(NEW) END;
    v_actor TEXT := NULLIF(current_setting('cyber_sentinel_ai.actor', true), '');
BEGIN
    -- Weekly Tranco sync: thousands of rows, already logged in sync_log.
    IF TG_TABLE_NAME = 'domain_allowlist'
       AND COALESCE(v_new->>'source', v_old->>'source') = 'tranco' THEN
        RETURN NULL;
    END IF;

    -- Skip no-op UPDATEs (same row before and after).
    IF TG_OP = 'UPDATE' AND v_old = v_new THEN
        RETURN NULL;
    END IF;

    INSERT INTO cyber_sentinel_ai.config_change_log
        (actor, db_user, table_name, operation, row_key, old_data, new_data)
    VALUES (
        COALESCE(v_actor, session_user::text),
        session_user::text,
        TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME,
        TG_OP,
        COALESCE(v_new, v_old)->>TG_ARGV[0],
        v_old,
        v_new
    );
    RETURN NULL;
END
$$;

DO $$
DECLARE
    t RECORD;
BEGIN
    FOR t IN
        SELECT * FROM (VALUES
            ('cyber_sentinel_ai', 'ai_settings',                 'key'),
            ('cyber_sentinel_ai', 'prompt_templates',            'version'),
            ('cyber_sentinel_ai', 'trusted_infrastructure',      'id'),
            ('cyber_sentinel_ai', 'domain_allowlist',            'domain'),
            ('cyber_sentinel_ai', 'domain_allowlist_exclusions', 'domain'),
            ('cyber_sentinel',    'dic_threat_levels',           'score')
        ) AS v(schema_name, table_name, pk)
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS trg_config_change_log ON %I.%I',
                       t.schema_name, t.table_name);
        EXECUTE format(
            'CREATE TRIGGER trg_config_change_log
                 AFTER INSERT OR UPDATE OR DELETE ON %I.%I
                 FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_config_change_log(%L)',
            t.schema_name, t.table_name, t.pk);
    END LOOP;
END
$$;

-- ============================================
-- SECTION 3: ai_settings — updated_at maintenance
-- ============================================
-- The editor role may only SET value, so updated_at is maintained here.

CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_ai_settings_touch()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.value IS DISTINCT FROM OLD.value THEN
        NEW.updated_at := LOCALTIMESTAMP;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_ai_settings_touch ON cyber_sentinel_ai.ai_settings;
CREATE TRIGGER trg_ai_settings_touch
    BEFORE UPDATE ON cyber_sentinel_ai.ai_settings
    FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_ai_settings_touch();

-- ============================================
-- SECTION 4: prompt_templates — guards
-- ============================================
-- 1. The ACTIVE prompt is what n8n uses right now: its text cannot be
--    changed in place and it cannot be deleted. Workflow: copy -> edit the
--    draft -> activate it.
-- 2. Exactly one active prompt at COMMIT (playbook 04.3 [04.3.2.1] and
--    the workflow both depend on that). Activation therefore runs as two
--    UPDATEs in one transaction: old one off, new one on. The existing
--    partial unique index already blocks two active rows; this deferred
--    trigger blocks ZERO active rows.

CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_prompt_guard()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.is_active THEN
            RAISE EXCEPTION 'Prompt version % is active and cannot be deleted - activate another version first', OLD.version;
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.is_active AND NEW.system_prompt IS DISTINCT FROM OLD.system_prompt THEN
        RAISE EXCEPTION 'Prompt version % is active - its text cannot be edited; create a new version instead', OLD.version;
    END IF;
    IF NEW.version IS DISTINCT FROM OLD.version THEN
        RAISE EXCEPTION 'Prompt version names cannot be renamed (verdict_audit.prompt_version references them)';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS trg_prompt_guard ON cyber_sentinel_ai.prompt_templates;
CREATE TRIGGER trg_prompt_guard
    BEFORE UPDATE OR DELETE ON cyber_sentinel_ai.prompt_templates
    FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_prompt_guard();

CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_prompt_one_active()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_active INT;
BEGIN
    SELECT count(*) INTO v_active
    FROM cyber_sentinel_ai.prompt_templates
    WHERE is_active;

    IF v_active <> 1 THEN
        RAISE EXCEPTION 'Exactly one prompt version must be active (found %)', v_active;
    END IF;
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS trg_prompt_one_active ON cyber_sentinel_ai.prompt_templates;
CREATE CONSTRAINT TRIGGER trg_prompt_one_active
    AFTER INSERT OR UPDATE OR DELETE ON cyber_sentinel_ai.prompt_templates
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_prompt_one_active();

-- ============================================
-- SECTION 4b: dic_threat_levels — malicious flag guard
-- ============================================
-- is_malicious_flag decides what every Grafana view counts as malicious
-- (v_grafana_malicious_stats, _daily_trends, _threat_explorer,
-- _threat_alerts). The views join the dictionary at query time, so a
-- change is retroactive for all historical verdicts.
-- Guard: the flags must form one contiguous top range (score >= N), and
-- the highest score must be malicious. "3 malicious but 4 not" would
-- make Grafana count a weaker verdict as worse than a stronger one.
-- Deferred, so one transaction can flip several rows.

CREATE OR REPLACE FUNCTION cyber_sentinel_ai.trg_threat_levels_malicious()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_min_malicious INT;
    v_bad INT;
BEGIN
    SELECT min(score) INTO v_min_malicious
    FROM cyber_sentinel.dic_threat_levels WHERE is_malicious_flag;

    IF v_min_malicious IS NULL THEN
        RAISE EXCEPTION 'At least the highest threat level must be marked malicious';
    END IF;

    SELECT count(*) INTO v_bad
    FROM cyber_sentinel.dic_threat_levels
    WHERE score >= v_min_malicious AND NOT is_malicious_flag;

    IF v_bad > 0 THEN
        RAISE EXCEPTION 'Malicious levels must be a contiguous top range (every level from % upwards)', v_min_malicious;
    END IF;
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS trg_threat_levels_malicious ON cyber_sentinel.dic_threat_levels;
CREATE CONSTRAINT TRIGGER trg_threat_levels_malicious
    AFTER UPDATE OF is_malicious_flag ON cyber_sentinel.dic_threat_levels
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION cyber_sentinel_ai.trg_threat_levels_malicious();

-- ============================================
-- SECTION 5: MANUAL ALLOW-LIST VIEW
-- ============================================
-- Simple single-table view => automatically updatable. DML on it runs with
-- the VIEW OWNER's privileges on the base table, so the editor role needs
-- no DML grant on domain_allowlist itself. WITH CHECK OPTION rejects any
-- INSERT/UPDATE whose result would not be source = 'manual'; UPDATE and
-- DELETE can only ever reach rows the view shows. The base table's CHECK
-- constraints (lower-case, contains a dot) still apply.

CREATE OR REPLACE VIEW cyber_sentinel_ai.v_manual_allowlist AS
SELECT domain, source, rank, is_active, note, first_added, updated_at, removed_at
FROM cyber_sentinel_ai.domain_allowlist
WHERE source = 'manual'
WITH CASCADED CHECK OPTION;

-- ============================================
-- SECTION 6: GRANTS
-- ============================================
-- Explicit per object. Nothing is granted on ALL TABLES and no default
-- privileges are set for this role, so tables added to either schema
-- later stay invisible to it until granted here on purpose.

GRANT SELECT                  ON cyber_sentinel_ai.ai_settings                 TO "{{ ai_config_db_user }}";
GRANT UPDATE (value)          ON cyber_sentinel_ai.ai_settings                 TO "{{ ai_config_db_user }}";

GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_sentinel_ai.prompt_templates            TO "{{ ai_config_db_user }}";
GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_sentinel_ai.trusted_infrastructure      TO "{{ ai_config_db_user }}";
GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_sentinel_ai.domain_allowlist_exclusions TO "{{ ai_config_db_user }}";
GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_sentinel_ai.v_manual_allowlist          TO "{{ ai_config_db_user }}";

GRANT SELECT ON cyber_sentinel_ai.domain_allowlist          TO "{{ ai_config_db_user }}";
GRANT SELECT ON cyber_sentinel_ai.domain_allowlist_sync_log TO "{{ ai_config_db_user }}";
GRANT SELECT ON cyber_sentinel_ai.config_change_log         TO "{{ ai_config_db_user }}";

GRANT SELECT                                   ON cyber_sentinel.dic_threat_levels        TO "{{ ai_config_db_user }}";
GRANT UPDATE (description, action_recommended, is_malicious_flag) ON cyber_sentinel.dic_threat_levels TO "{{ ai_config_db_user }}";
GRANT SELECT                                   ON cyber_sentinel.v_threat_scale_for_agent TO "{{ ai_config_db_user }}";

-- The n8n app role keeps full access to the AI schema (default privileges
-- in db_ai_pipeline.sql); grant it the new objects explicitly as well, in
-- case this file runs on a database where default privileges were altered.
GRANT SELECT ON cyber_sentinel_ai.config_change_log  TO "{{ postgres_user }}";
GRANT SELECT ON cyber_sentinel_ai.v_manual_allowlist TO "{{ postgres_user }}";

-- The schema's default privileges (db_ai_pipeline.sql, Section 1) hand the
-- n8n role INSERT/UPDATE/DELETE on every new table — including this log.
-- The audit trail must be append-only via the trigger, so take those back.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON cyber_sentinel_ai.config_change_log FROM "{{ postgres_user }}";

-- Functions used read-only by the UI (simulator, allow-list check) run with
-- the caller's privileges and are EXECUTE-able by PUBLIC by default; they
-- only read tables granted above.

-- ============================================
-- VERIFICATION (run manually)
-- ============================================
-- \dp cyber_sentinel_ai.*
-- SELECT * FROM cyber_sentinel_ai.config_change_log ORDER BY changed_at DESC LIMIT 20;
-- As the editor role, all of these must FAIL:
--   DELETE FROM cyber_sentinel_ai.ai_settings WHERE key = 'cache_ttl_days';
--   UPDATE cyber_sentinel_ai.ai_settings SET description = 'x';
--   UPDATE cyber_sentinel_ai.domain_allowlist SET is_active = false;
--   INSERT INTO cyber_sentinel_ai.v_manual_allowlist (domain, source) VALUES ('x.com', 'tranco');
--   SELECT * FROM cyber_sentinel.dns_queries LIMIT 1;
-- ============================================
