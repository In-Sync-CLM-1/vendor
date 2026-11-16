import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const token = authHeader.replace("Bearer ", "");
    const { data: claimsData, error: claimsError } = await userClient.auth.getClaims(token);
    if (claimsError || !claimsData?.claims) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const userId = claimsData.claims.sub;
    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const { data: isAdmin } = await adminClient.rpc("is_admin", { _user_id: userId });

    if (!isAdmin) {
      return new Response(JSON.stringify({ error: "Admin access required" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { encryption_key, action } = await req.json();

    if (action === "check") {
      const { data: exists } = await adminClient.rpc("check_encryption_key_exists");
      return new Response(
        JSON.stringify({ configured: !!exists }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Save action. The key is shared by every organisation, so only a platform admin may set it,
    // and only once: replacing it would leave every record encrypted with the old key unreadable.
    const { data: isPlatformAdmin } = await adminClient.rpc("is_platform_admin", { _user_id: userId });
    if (!isPlatformAdmin) {
      return new Response(JSON.stringify({ error: "Only the platform administrator can set the encryption key" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const { data: alreadySet } = await adminClient.rpc("check_encryption_key_exists");
    if (alreadySet) {
      return new Response(JSON.stringify({ error: "The encryption key is already set and cannot be replaced" }), {
        status: 409,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    if (!encryption_key || typeof encryption_key !== "string" || encryption_key.length < 16) {
      return new Response(
        JSON.stringify({ error: "Encryption key must be at least 16 characters" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const { error: upsertError } = await adminClient.rpc("upsert_vault_secret", {
      secret_name: "PII_ENCRYPTION_KEY",
      secret_value: encryption_key,
    });

    if (upsertError) {
      throw new Error(`Failed to update encryption key: ${upsertError.message}`);
    }

    return new Response(
      JSON.stringify({ success: true, message: "Encryption key updated successfully" }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
