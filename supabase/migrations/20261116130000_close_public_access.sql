-- Code audit 2026-11-15 (approved), Vendorsync: nobody without a sign-in reaches Vendorsync data or actions,
-- the encryption key and the decrypt step are for the server only, and staff see vendor bank/PAN/GST
-- details only for vendors of their own organisation.
-- Public pages keep working: the vendor referral form reads the category and document lists and the
-- organisation's logo and name; every other public step (OTP, referral check, uploads, submit, organisation
-- sign-up, invoice approval links) runs in server functions with the system key.

-- 1. Encryption key and decrypt/encrypt steps: server only. The site never calls them; the database's own
--    steps (vendor/profile encryption on save, the two detail look-ups below) run as the database owner.
DO $$ DECLARE f record; BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace
           AND p.proname = ANY (ARRAY['upsert_vault_secret','decrypt_pii','encrypt_pii','check_encryption_key_exists',
                                      'increment_vendor_usage','refresh_invoice_payment_status']) LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', f.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f.sig);
  END LOOP;
END $$;
-- The two decrypted views are not used by any screen; only server code may read them.
REVOKE ALL ON public.vendors_decrypted FROM anon, authenticated;
REVOKE ALL ON public.profiles_decrypted FROM anon, authenticated;
GRANT SELECT ON public.vendors_decrypted, public.profiles_decrypted TO service_role;

-- 2. Vendor detail look-ups: staff only for vendors of their own organisation (platform admins: any).
CREATE OR REPLACE FUNCTION public.get_vendor_decrypted(p_vendor_id uuid)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  result JSON;
  calling_user UUID;
  v_tenant_id UUID;
BEGIN
  calling_user := auth.uid();

  SELECT tenant_id INTO v_tenant_id FROM public.vendors WHERE id = p_vendor_id;

  IF is_internal_staff(calling_user) OR is_admin(calling_user) THEN
    IF NOT (is_platform_admin(calling_user) OR v_tenant_id = get_user_tenant_id(calling_user)) THEN
      RAISE EXCEPTION 'Unauthorized';
    END IF;
  ELSIF NOT (is_vendor_user(calling_user) AND p_vendor_id = get_vendor_id(calling_user)) THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  INSERT INTO public.pii_access_log (user_id, tenant_id, table_name, column_name, vendor_id, purpose)
  VALUES (calling_user, v_tenant_id, 'vendors', 'all_pii_fields', p_vendor_id, 'vendor_detail_view');

  SELECT json_build_object(
    'id', v.id, 'vendor_code', v.vendor_code, 'category_id', v.category_id,
    'company_name', v.company_name, 'trade_name', v.trade_name,
    'registered_address', v.registered_address, 'operational_address', v.operational_address,
    'primary_contact_name', v.primary_contact_name, 'secondary_contact_name', v.secondary_contact_name,
    'salutation', v.salutation, 'constitution_type', v.constitution_type,
    'nominee_name', v.nominee_name, 'bank_name', v.bank_name, 'bank_branch', v.bank_branch,
    'current_status', v.current_status, 'submitted_at', v.submitted_at,
    'approved_at', v.approved_at, 'rejected_at', v.rejected_at,
    'rejection_reason', v.rejection_reason, 'sent_back_reason', v.sent_back_reason,
    'referred_by', v.referred_by, 'created_at', v.created_at, 'updated_at', v.updated_at,
    'pan_number', COALESCE(decrypt_pii(v.pan_number_encrypted), v.pan_number),
    'gst_number', COALESCE(decrypt_pii(v.gst_number_encrypted), v.gst_number),
    'cin_number', COALESCE(decrypt_pii(v.cin_number_encrypted), v.cin_number),
    'bank_account_number', COALESCE(decrypt_pii(v.bank_account_number_encrypted), v.bank_account_number),
    'bank_ifsc', COALESCE(decrypt_pii(v.bank_ifsc_encrypted), v.bank_ifsc),
    'primary_mobile', COALESCE(decrypt_pii(v.primary_mobile_encrypted), v.primary_mobile),
    'primary_email', COALESCE(decrypt_pii(v.primary_email_encrypted), v.primary_email),
    'secondary_mobile', COALESCE(decrypt_pii(v.secondary_mobile_encrypted), v.secondary_mobile),
    'nominee_contact', COALESCE(decrypt_pii(v.nominee_contact_encrypted), v.nominee_contact)
  ) INTO result
  FROM public.vendors v WHERE v.id = p_vendor_id;

  RETURN result;
END;
$function$;

CREATE OR REPLACE FUNCTION public.get_vendor_sensitive_info(p_vendor_id uuid)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions'
AS $function$
DECLARE
  result JSON;
  calling_user UUID;
  v_tenant_id UUID;
BEGIN
  calling_user := auth.uid();

  IF public.is_view_only(calling_user) THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  IF NOT (is_internal_staff(calling_user) OR is_admin(calling_user)) THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  SELECT tenant_id INTO v_tenant_id FROM public.vendors WHERE id = p_vendor_id;

  IF v_tenant_id IS NOT NULL
     AND NOT (is_platform_admin(calling_user) OR v_tenant_id = get_user_tenant_id(calling_user)) THEN
    RAISE EXCEPTION 'Unauthorized';
  END IF;

  INSERT INTO public.pii_access_log (user_id, tenant_id, table_name, column_name, vendor_id, purpose)
  VALUES (calling_user, v_tenant_id, 'vendors', 'sensitive_info_fields', p_vendor_id, 'sensitive_info_lookup');

  SELECT json_build_object(
    'id', v.id, 'vendor_code', v.vendor_code, 'company_name', v.company_name,
    'current_status', v.current_status,
    'primary_email', COALESCE(decrypt_pii(v.primary_email_encrypted), v.primary_email),
    'primary_mobile', COALESCE(decrypt_pii(v.primary_mobile_encrypted), v.primary_mobile),
    'secondary_mobile', COALESCE(decrypt_pii(v.secondary_mobile_encrypted), v.secondary_mobile),
    'bank_name', v.bank_name, 'bank_branch', v.bank_branch,
    'bank_account_number', COALESCE(decrypt_pii(v.bank_account_number_encrypted), v.bank_account_number),
    'bank_ifsc', COALESCE(decrypt_pii(v.bank_ifsc_encrypted), v.bank_ifsc),
    'pan_number', COALESCE(decrypt_pii(v.pan_number_encrypted), v.pan_number),
    'gst_number', COALESCE(decrypt_pii(v.gst_number_encrypted), v.gst_number),
    'cin_number', COALESCE(decrypt_pii(v.cin_number_encrypted), v.cin_number),
    'msme_number', COALESCE(decrypt_pii(v.msme_number_encrypted), v.msme_number)
  ) INTO result
  FROM public.vendors v WHERE v.id = p_vendor_id;

  IF result IS NULL THEN
    RAISE EXCEPTION 'Vendor not found';
  END IF;

  RETURN result;
END;
$function$;

-- 3. Open table rules. Vendor records, consent records and the personal-data access log are written by
--    server functions with the system key (or by the database's own steps), so the "anyone may add" rules go.
DROP POLICY IF EXISTS "Allow vendor creation via edge function" ON public.vendors;
DROP POLICY IF EXISTS "Allow consent insertion via edge function" ON public.consent_records;
DROP POLICY IF EXISTS "System can insert audit log" ON public.pii_access_log;
-- Referral codes: the referral link is checked by the validate-referral-code server function; staff see
-- their own code and admins their organisation's codes (existing rules), nobody else lists them.
DROP POLICY IF EXISTS "Public can validate referral codes" ON public.staff_referral_codes;
-- Organisation records: only the platform admin manages organisations (organisation admins used to match too).
DROP POLICY IF EXISTS "Platform admins manage tenants" ON public.tenants;
CREATE POLICY "Platform admins manage tenants" ON public.tenants
  FOR ALL TO authenticated
  USING (public.is_platform_admin(auth.uid()))
  WITH CHECK (public.is_platform_admin(auth.uid()));

-- 4. Visitors without a sign-in: nothing from tables, except what the public pages show.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON TABLES FROM anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE ALL ON SEQUENCES FROM anon;
GRANT SELECT ON public.vendor_categories, public.category_documents, public.document_types,
                public.subscription_plans TO anon;
-- Organisation branding only (name, logo, colours, public contact and privacy details); never the
-- organisation's tax numbers, billing address or sender settings.
GRANT SELECT (id, slug, name, short_name, logo_url, primary_color, accent_color, vendor_code_prefix,
              dpo_email, privacy_policy_url, support_email, support_phone, is_active)
  ON public.tenants TO anon;

-- 5. Functions: closed to visitors without a sign-in. Signed-in access stays exactly as it was
--    (functions already closed to signed-in people stay closed), except the server-only ones in step 1.
DO $$ DECLARE f record; BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace
           AND has_function_privilege('authenticated', p.oid, 'EXECUTE') LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO authenticated', f.sig);
  END LOOP;
END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO service_role;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon;
