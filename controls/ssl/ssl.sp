locals {
  ssl_best_practices_common_tags = merge(local.net_insights_common_tags, {
    service = "Net/SSL"
  })
}

benchmark "ssl_best_practices" {
  title       = "SSL Best Practices"
  description = "Best practices for your certificates."
  documentation = file("./controls/docs/ssl_overview.md")
  
  children = [
    benchmark.ssl_certificate_best_practices,
    benchmark.ssl_configuration_best_practices,
    control.ssl_certificate_too_much_security,
    #control.ssl_http_strict_transport_security_enabled,
    #control.ssl_content_security_policy_enabled
  ]

  tags = merge(local.ssl_best_practices_common_tags, {
    type = "Benchmark"
  })
}

control "ssl_certificate_too_much_security" {
  title       = "Too much security"
  description = "Using RSA keys stronger than 2,048 bits and ECDSA keys stronger than 256 bits is a waste of CPU power and might impair user experience."

  sql = <<-EOT
    select
      common_name as resource,
      case
        when (public_key_algorithm = 'RSA' and public_key_length > 2048) then 'alarm'
        when (public_key_algorithm = 'ECDSA' and public_key_length > 256) then 'alarm'
        else 'ok'
      end as status,
      case
        when (
          (public_key_algorithm = 'RSA' and public_key_length > 2048)
          or
          (public_key_algorithm = 'ECDSA' and public_key_length > 256)
        ) then common_name || ' is using too big keys.'
        else common_name || ' is not using big keys.'
      end as reason
    from
      net_certificate
    where
      domain in (select jsonb_array_elements_text(to_jsonb($1::text[])))
    order by common_name;
  EOT

  param "dns_domain_names" {
    description = "DNS domain names."
    default     = var.dns_domain_names
  }
}

# TODO:: The following checks required updated `net_web_request` table.
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
