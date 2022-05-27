# benchmark "ssl_http_and_application_security" {
#   title         = "SSL/TLS HTTP and Application Security Best Practices"
#   description   = "Best practices for your SSL/TLS HTTP and Application Security."
#   documentation = file("./controls/docs/ssl_http_and_application_security_overview.md")
# 
#   children = [
#     control.ssl_http_strict_transport_security_enabled,
#     control.ssl_content_security_policy_enabled,
#     control.ssl_cache_sensitive_content_disabled,
#     control.ssl_website_cookies_not_secured,
#   ]
# 
#   tags = merge(local.ssl_best_practices_common_tags, {
#     type = "Benchmark"
#   })
# }
# 
# #TODO:: The following checks required updated `net_web_request` table.
# control "ssl_http_strict_transport_security_enabled" {
#   title       = "Websites should have HTTP Strict Transport Security (HSTS) enabled"
#   description = ""
# 
#   sql = <<-EOT
#     with available_headers as (
#       select
#         url,
#         array_agg(header.key)
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#       group by url
#     )
#     select
#       url as resource,
#       case
#         when array['Strict-Transport-Security'] <@ array_agg then 'ok'
#         else 'alarm'
#       end as status,
#       case
#         when array['Strict-Transport-Security'] <@ array_agg then url || ' contains required headers ''Strict-Transport-Security''.'
#         else url || ' has missing required headers ''Strict-Transport-Security''.'
#       end as reason
#     from
#       available_headers;
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
# 
# control "ssl_content_security_policy_enabled" {
#   title       = "Websites should have Content Security Policy (CSP) enabled"
#   description = ""
# 
#   sql = <<-EOT
#     with available_headers as (
#       select
#         url,
#         array_agg(header.key)
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#       group by url
#     )
#     select
#       url as resource,
#       case
#         when array['Content-Security-Policy'] <@ array_agg then 'ok'
#         else 'alarm'
#       end as status,
#       case
#         when array['Content-Security-Policy'] <@ array_agg then url || ' contains required headers ''Content-Security-Policy''.'
#         else url || ' has missing required headers ''Content-Security-Policy''.'
#       end as reason
#     from
#       available_headers;
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
# 
# control "ssl_cache_sensitive_content_disabled" {
#   title         = "Sensitive contents should not be cached"
#   documentation = file("./controls/docs/ssl_cache_sensitive_content.md")
# 
#   sql = <<-EOT
#     with domains as (
#       select domain from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
#     ),
#     cache_control_headers as (
#       select
#         url,
#         header.key,
#         (
#           select
#             string_agg(txt, ', ') as value
#           from (
#             select jsonb_array_elements_text(header.value) as txt
#           ) header_values
#         )
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#         and header.key = 'Cache-Control'
#     )
#     select
#       d.domain as resource,
#       case
#         when c.url is null then 'alarm'
#         when not c.value ~ 'max-age=0, private, must-revalidate' then 'alarm'
#         else 'ok'
#       end as status,
#       case
#         when c.url is null then d.domain || ' has missing headers ''Cache-Control''.'
#         when not c.value ~ 'max-age=0, private, must-revalidate' then 'Caching sensitive content is disabled for ' || d.domain || '.'
#         else 'Caching sensitive content is enabled for ' || d.domain || '.'
#       end as reason
#     from
#       domains as d
#       left join cache_control_headers as c on concat('https://', d.domain) = c.url
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
# 
# control "ssl_website_cookies_not_secured" {
#   title         = "Websites cookies should be secured"
#   description   = "Cookies are small files that websites send to your device that the sites then use to monitor you and remember certain information about you. If the cookies are not secured, an active man-in-the-middle (MITM) attacker can tease some information out through clever tricks. Adding HttpOnly and Secure in the `Set-Cookie` header can prevent web vulnerabilities such as cross-site scripting (XSS)."
# 
#   sql = <<-EOT
#     with domains as (
#       select domain from jsonb_array_elements_text(to_jsonb($1::text[])) as domain
#     ),
#     cache_control_headers as (
#       select
#         url,
#         header.key,
#         (
#           select
#             string_agg(txt, ', ') as value
#           from (
#             select jsonb_array_elements_text(header.value) as txt
#           ) header_values
#         )
#       from
#         net_web_request,
#         jsonb_each(response_headers) as header
#       where
#         url in (select concat('https://', jsonb_array_elements_text(to_jsonb($1::text[]))))
#         and header.key = 'Set-Cookie'
#     )
#     select
#       d.domain as resource,
#       case
#         when c.url is null then 'alarm'
#         when not c.value ~ 'HttpOnly; Secure' then 'alarm'
#         else 'ok'
#       end as status,
#       case
#         when c.url is null then d.domain || ' has missing headers ''Set-Cookie''.'
#         when not c.value ~ 'HttpOnly; Secure' then d.domain || ' cookies are secured.'
#         else d.domain || ' cookies are not secured.'
#       end as reason
#     from
#       domains as d
#       left join cache_control_headers as c on concat('https://', d.domain) = c.url
#   EOT
# 
#   param "dns_domain_names" {
#     description = "DNS domain names."
#     default     = var.dns_domain_names
#   }
# }
