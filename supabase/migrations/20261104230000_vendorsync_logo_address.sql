-- Organisation logos moved to the vendorsync-public bucket, which has its own
-- public address. Triggers are off because this is an address change only.
ALTER TABLE public.tenants DISABLE TRIGGER USER;

UPDATE public.tenants
   SET logo_url = replace(logo_url, 'pub-cd2c094f9eef4c8993bc1f4b55a0e7b1.r2.dev', 'pub-847d742a808d41dd8b23f3aee9062fda.r2.dev')
 WHERE logo_url LIKE '%pub-cd2c094f9eef4c8993bc1f4b55a0e7b1.r2.dev%';

ALTER TABLE public.tenants ENABLE TRIGGER USER;
