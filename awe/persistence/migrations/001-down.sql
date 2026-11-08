-- DESTRUCTIVE: disposable test database only. Production rollback requires an
-- independently reviewed forward migration and preserved invoices/audit/backups.
BEGIN;
DROP SCHEMA awe_d09 CASCADE;
DROP ROLE awe_d09_api;
DROP ROLE awe_d09_reconciler;
DROP ROLE awe_d09_reader;
DROP ROLE awe_d09_issuer;
DROP ROLE awe_d09_owner;
COMMIT;
