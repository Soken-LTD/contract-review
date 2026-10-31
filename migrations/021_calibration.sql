-- Migration 021: severity calibration beside the reviewer's severity (thin server, CEO decision 2026-10-31).
--
-- finding_drafts.severity is the printed severity: the reviewer's claimed_severity, final. The matrix outcome
-- (IxL cell and every K cap or step that applies) is kept as the calibration, which the report prints beside
-- the finding as "Calibration: <calibration_severity> (<calibration_rule>)" when it differs.
-- Additive: nullable columns, no existing row changes (a null calibration prints nothing).
alter table finding_drafts add column if not exists calibration_severity text
  check (calibration_severity is null
         or calibration_severity in ('Critical','High','Medium','Low','Informational'));
alter table finding_drafts add column if not exists calibration_rule text;
