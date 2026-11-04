-- Work-Sync TASK-2775: as per the client rule, an invoice may be up to 30% above
-- the PO amount. Anything higher is still refused. The rest of the function is
-- unchanged from the live definition.
CREATE OR REPLACE FUNCTION public.submit_invoice_on_row(p_id uuid, p_number text, p_date date, p_amount numeric, p_gst numeric, p_description text, p_file_key text, p_due date, p_ai_data jsonb, p_ai_confidence integer, p_ai_model text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  r public.vendor_invoices%ROWTYPE;
  v_po public.purchase_orders;
BEGIN
  SELECT * INTO r FROM public.vendor_invoices WHERE id = p_id;
  IF NOT FOUND OR r.doc_stage NOT IN ('proforma_invoice', 'quotation') THEN
    RAISE EXCEPTION 'This PI/Quotation has already been invoiced';
  END IF;
  IF NOT (is_vendor_user(auth.uid()) AND r.vendor_id = get_vendor_id(auth.uid())) THEN
    RAISE EXCEPTION 'Not authorised';
  END IF;
  IF (SELECT current_status FROM public.vendors WHERE id = r.vendor_id) <> 'approved'::public.vendor_status THEN
    RAISE EXCEPTION 'Only approved vendors can submit invoices';
  END IF;
  IF r.status <> 'approved'::public.invoice_status THEN
    RAISE EXCEPTION 'The PI/Quotation has not been approved';
  END IF;
  SELECT * INTO v_po FROM public.purchase_orders WHERE invoice_id = p_id OR pi_quotation_id = p_id LIMIT 1;
  IF v_po.id IS NULL THEN
    RAISE EXCEPTION 'No Purchase Order has been issued yet -- an invoice cannot be submitted without one';
  END IF;
  IF trim(coalesce(p_number, '')) = '' OR p_date IS NULL OR p_amount IS NULL OR p_amount <= 0 OR p_file_key IS NULL THEN
    RAISE EXCEPTION 'Invoice number, date, amount and file are needed';
  END IF;
  -- Client rule: an invoice may run up to 30% above the PO.
  IF p_amount > v_po.grand_total * 1.3 + 1 THEN
    RAISE EXCEPTION 'The invoice (%) is more than 30%% above the PO amount (%)',
      to_char(p_amount, 'FM999,999,999.00'), to_char(v_po.grand_total, 'FM999,999,999.00');
  END IF;

  PERFORM set_config('app.unified_rpc', '1', true);
  UPDATE public.vendor_invoices
     SET doc_stage = 'invoice',
         invoice_number = trim(p_number),
         invoice_date = p_date,
         invoice_amount = p_amount,
         gst_amount = COALESCE(p_gst, 0),
         description = p_description,
         invoice_file_key = p_file_key,
         due_date = p_due,
         po_number = v_po.po_number,
         ai_extracted_data = p_ai_data,
         ai_confidence_score = p_ai_confidence,
         ai_model_version = p_ai_model,
         status = 'submitted'::public.invoice_status,
         rejection_reason = NULL, reviewed_by = NULL, reviewed_at = NULL
   WHERE id = p_id;

  PERFORM public.refresh_invoice_payment_status(p_id);
END;
$function$;
