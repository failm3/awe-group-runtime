-- Operator-only; disposable INT03 cluster ONLY. D09 tables remain untouched.
BEGIN;
DROP SCHEMA awe_int03 CASCADE;
DROP ROLE awe_int03_host, awe_int03_verifier, awe_int03_evaluator, awe_int03_owner;
COMMIT;
