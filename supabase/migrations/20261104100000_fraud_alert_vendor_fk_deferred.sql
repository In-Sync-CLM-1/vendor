-- Work-Sync TASK-2833: a vendor whose GST, PAN or bank details matched an existing
-- vendor could not register. detect_vendor_duplicates() runs BEFORE INSERT, because
-- it has to read the plain values before encrypt_vendor_pii_trigger clears them, so
-- it files the fraud alert before the vendor row exists. The foreign key rejected
-- that alert and the whole submission failed. Checking the key at commit lets the
-- vendor and its alert be saved together, so staff can review the alert as intended.
ALTER TABLE public.fraud_alerts DROP CONSTRAINT fraud_alerts_vendor_id_fkey;
ALTER TABLE public.fraud_alerts
  ADD CONSTRAINT fraud_alerts_vendor_id_fkey
  FOREIGN KEY (vendor_id) REFERENCES public.vendors(id) ON DELETE CASCADE
  DEFERRABLE INITIALLY DEFERRED;
