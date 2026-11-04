import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SUREPASS_BASE_URL = Deno.env.get("SUREPASS_BASE_URL") || "https://sandbox.surepass.app";
const SUREPASS_TOKEN = Deno.env.get("SUREPASS_TOKEN") || "";

async function retryWithBackoff(fn: () => Promise<Response>, maxRetries = 2) {
  for (let i = 0; i <= maxRetries; i++) {
    try {
      const response = await fn();
      if (response.ok || response.status === 200 || response.status === 422) return response;
      if (response.status >= 500 && i < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
        continue;
      }
      return response;
    } catch (error) {
      if (i < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
        continue;
      }
      throw error;
    }
  }
  throw new Error("Max retries exceeded");
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { vpa, vendor_id } = await req.json();

    if (!vpa || !/^[\w.\-]+@[\w.\-]+$/.test(vpa)) {
      return new Response(
        JSON.stringify({ success: false, error: "Invalid UPI VPA format. Expected format: user@provider" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    const { data: vendor } = await supabase.from("vendors").select("tenant_id").eq("id", vendor_id).maybeSingle();

    const verificationId = crypto.randomUUID();
    await supabase.from("vendor_checks").insert({
      id: verificationId,
      vendor_id,
      tenant_id: vendor?.tenant_id,
      verification_type: "upi",
      verification_source: "surepass",
      status: "in_progress",
      request_data: { vpa },
    });

    const response = await retryWithBackoff(() =>
      fetch(`${SUREPASS_BASE_URL}/api/v1/bank-verification/upi-verification`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${SUREPASS_TOKEN}`,
        },
        body: JSON.stringify({ id_number: vpa }),
      })
    );

    const responseText = await response.text();
    let responseData: any;
    try {
      responseData = JSON.parse(responseText);
    } catch {
      await supabase.from("vendor_checks").update({
        status: "error",
        response_data: { raw: responseText, http_status: response.status },
      }).eq("id", verificationId);
      return new Response(
        JSON.stringify({ success: false, error: "Verification service returned an invalid response." }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const isValid = responseData.success && responseData.data;
    const verificationStatus = isValid ? "success" : "failed";

    await supabase.from("vendor_checks").update({
      status: verificationStatus,
      response_data: responseData.data || responseData,
      verified_at: new Date().toISOString(),
    }).eq("id", verificationId);

    if (!isValid) {
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            vpa,
            name: null,
            is_valid: false,
            status: "failed",
          },
        }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        data: {
          vpa: responseData.data.vpa || vpa,
          name: responseData.data.name || responseData.data.account_holder_name,
          is_valid: true,
          status: "success",
        },
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("UPI verification error:", error);
    return new Response(
      JSON.stringify({ success: false, error: error instanceof Error ? error.message : "Verification failed" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
